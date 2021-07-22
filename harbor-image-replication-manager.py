#!python3

# Copyright 2021 SVA System Vertrieb Alexander GmbH

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Author: Niko Wenselowski <niko.wenselowski@sva.de>
"""
Harbor Image Replication Manager
"""

import argparse
import json
import logging
import time
from collections import namedtuple
from functools import partial
from urllib.parse import quote

import requests
from requests.auth import HTTPBasicAuth

__version__ = "1.0.0"
DELETION_SLEEP_TIME = 10

Image = namedtuple("Image", "namespace name tag")

logger = logging.getLogger("replication-manager")


def main():
    options = parse_cli()

    if options.verbosity:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if not options.verify_cert:
        import urllib3

        urllib3.disable_warnings()

    h = HarborClient(
        options.base_url, options.username, options.password, options.verify_cert
    )
    manager = HarborManager(
        h,
        replication_rule_prefix=options.rule_prefix,
        trigger_execution=options.trigger,
    )

    if options.mode == "create":
        if not options.registry:
            raise RuntimeError("No registry given for rule!")

        registry = h.get_registry(options.registry)
        process_func = partial(manager.replicate_image, registry=registry)
    elif options.mode == "delete":
        process_func = partial(
            manager.remove_image_replication, delete_projects=options.delete_projects
        )
    else:
        raise RuntimeError(f"Invalid mode: {options.mode!r}")

    images = get_images(options.imagefile)
    for image in images:
        process_func(image)


def parse_cli():
    parser = argparse.ArgumentParser(
        description="Manage your image replication to harbor with ease!",
        epilog="Made with <3 by SVA",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "-v", "--verbose", dest="verbosity", action="count", help="Verbose output"
    )
    parser.add_argument("--image-file", "-i", dest="imagefile", required=True)
    parser.add_argument(
        "--rule-prefix",
        dest="rule_prefix",
        default="hir-",
        help="The prefix for managed policies",
    )
    parser.add_argument(
        "--no-rule-trigger",
        dest="trigger",
        action="store_false",
        help="Trigger replication for policies",
    )
    parser.add_argument("mode", choices=["create", "delete"])

    harbor = parser.add_argument_group(
        "Harbor", description="Configuration for the connection to Harbor"
    )
    harbor.add_argument(
        "--harbor", dest="base_url", required=True, help="Harbor address"
    )
    harbor.add_argument(
        "--insecure",
        action="store_false",
        dest="verify_cert",
        help="Do not verify server certificates",
    )
    harbor.add_argument(
        "--user", dest="username", required=True, help="Username to use"
    )
    harbor.add_argument(
        "--password", dest="password", required=True, help="Password to use"
    )

    behaviour = parser.add_argument_group("Behavioural options")
    behaviour.add_argument(
        "--registry", help="Name of the registry to use when creating new policies"
    )
    behaviour.add_argument(
        "--delete-projects",
        dest="delete_projects",
        action="store_true",
        help="Delete projects (and not just rules) if deleting",
    )

    return parser.parse_args()


def get_images(image_file):
    with open(image_file) as imagefile:
        images = imagefile.readlines()

    return [split_image_line(image) for image in images]


def split_image_line(line):
    line = line.strip()
    try:
        namespace, image_and_tag = line.split("/", 1)
    except ValueError:
        namespace = "library"
        image_and_tag = line

    try:
        image, tag = image_and_tag.split(":", 1)
    except ValueError:
        image = image_and_tag
        tag = "latest"

    return Image(namespace, image, tag)


class HarborProject:
    def __init__(self, name, *, raw=None):
        self.name = name
        self._raw = raw or None

    def create(self, harbor_client):
        data = {
            "project_name": self.name,
            "cve_allowlist": {
                "update_time": "0001-01-01T00:00:00.000Z",
                "items": [],
                "project_id": 0,
                "creation_time": "0001-01-01T00:00:00.000Z",
                "id": 0,
                "expires_at": 0,
            },
            "public": True,
            "storage_limit": 0,
        }

        harbor_client.create_project(self.name, data)

        self._raw = harbor_client.get_project_json(self.name)

    def delete(self, harbor_client):
        if not self._raw:
            return

        if not harbor_client.is_project_deletable(self.name):
            harbor_client.remove_project_content(self.name)
            logger.info(f"Triggered emptying of {self.name}")

        logger.info(f"Waiting for project {self.name} to be empty")
        while not harbor_client.is_project_deletable(self.name):
            time.sleep(DELETION_SLEEP_TIME)
            logger.debug(f"Project {self.name} still exists...")

        harbor_client.delete_project(self.name)

    def exists(self):
        return bool(self._raw)

    @classmethod
    def from_json(cls, project_json):
        return HarborProject(project_json["name"], raw=project_json)


class ReplicationPolicy:
    def __init__(self, name, *, raw=None):
        self.name = name
        self._raw = raw or None

        try:
            self.tags = self._get_raw_tags()
        except TypeError:
            self.tags = set()

    def _get_raw_tags(self):
        tags = [
            tagfilter["value"]
            for tagfilter in self._raw["filters"]
            if tagfilter["type"] == "tag"
        ]

        if len(tags) > 1:
            raise RuntimeError("Invalid tag configuration at {self.name} detected!")

        logger.debug("Tags before transformation: %r", tags)
        try:
            tags = tags[0]
            if tags.startswith("{"):
                tags = tags[1:]
            if tags.endswith("}"):
                tags = tags[:-1]
            tags = set(tags.split(","))
            logger.debug("Tags after transformation: %r", tags)
            return tags
        except IndexError:
            logger.debug("Tag transformation failed")
            return set()

    @property
    def id(self):
        try:
            return self._raw["id"]
        except TypeError:
            raise RuntimeError("Policy not created on harbor.")

    def create(self, harbor_client, project_name, image, registry):
        tag = image.tag or "**"

        name = f"{image.namespace}/{image.name}"
        data = {
            "description": f"Managed by {__file__}",
            # Flattening: Since we have the same namespace as a project we
            # set this to 1 in order to have the same image path as before.
            "dest_namespace_replace_count": 1,
            "filters": [{"type": "name", "value": name}, {"type": "tag", "value": tag}],
            "dest_registry": {
                "creation_time": "0001-01-01T00:00:00.000Z",
                "credential": {"access_secret": "*****", "type": "secret"},
                "id": 0,
                "insecure": True,
                "name": "Local",
                "type": "harbor",
                "update_time": "0001-01-01T00:00:00.000Z",
                "url": "http://core:8080",
            },
            "src_registry": registry,
            "dest_namespace": project_name,
            "trigger": {"trigger_settings": {}, "type": "manual"},
            "replicate_deletion": True,
            "deletion": True,
            "override": True,
            "enabled": True,
            "name": self.name,
        }

        harbor_client.create_replication_policy(self.name, data)

        self._raw = harbor_client.get_replication_policy_json(self.name)
        self.tags = self._get_raw_tags()

    def update_filters(self, harbor_client):
        raw_tags = self._get_raw_tags()
        logger.debug(f"tags: {self.tags!r} (local) vs {raw_tags!r} (API)")

        if self.tags == raw_tags:
            # Filters match, no need for an update
            logger.debug(f"Tag filters of {self.name} already set")
            return

        new_filters = [
            oldfilter
            for oldfilter in self._raw["filters"]
            if oldfilter["type"] != "tag"
        ]
        new_tag_filter = {"type": "tag", "value": self._create_filter_expression()}
        new_filters.append(new_tag_filter)

        new_config = self._raw.copy()
        new_config["filters"] = new_filters

        policy_id = self._raw["id"]
        harbor_client.update_replication_policy(policy_id, new_config)

        self._raw = harbor_client.get_replication_policy_json(self.name)

    def _create_filter_expression(self):
        if not self.tags:
            return "**"  # Match everything

        if "**" in self.tags:
            return "**"

        return "{%s}" % ",".join(self.tags)

    def trigger_execution(self, harbor_client):
        harbor_client.trigger_replication_policy_execution(self.id)

    def delete(self, harbor_client):
        if not self._raw:
            return

        harbor_client.delete_replication_policy(self.id)

    def exists(self):
        return bool(self._raw)

    def __repr__(self):
        return "<ReplicationPolicy(name=%s)>" % self.name

    @classmethod
    def from_json(cls, policy_json):
        return ReplicationPolicy(policy_json["name"], raw=policy_json)


class HarborManager:
    def __init__(
        self, harbor_client, *, replication_rule_prefix, trigger_execution=True
    ):
        self._harbor_client = harbor_client
        self._replication_rule_prefix = replication_rule_prefix
        self._trigger_replication_rule = trigger_execution

        self._replication_policies = {
            policy.name: policy
            for policy in self._harbor_client.get_replication_policies()
        }
        self._projects = {
            project.name: project for project in self._harbor_client.get_projects()
        }

    def replicate_image(self, image, registry):
        logger.debug(f"Attempting to replicate {image} from {registry['name']}")

        project_name = image.namespace
        try:
            project = self._projects[project_name]
        except KeyError:
            logger.debug(f"Creating project {project_name}")
            project = HarborProject(project_name)
            project.create(self._harbor_client)
            self._projects[project_name] = project
            logger.info(f"Created project {project.name}")

        replication_rule_name = self.create_replication_rule_name(image)
        try:
            policy = self._replication_policies[replication_rule_name]
            logger.debug(f"Tags for {policy.name}: {policy.tags}")
            policy.tags.add(image.tag)
            policy.update_filters(self._harbor_client)
        except KeyError:
            logger.debug("policy %s does not exist" % replication_rule_name)
            policy = ReplicationPolicy(replication_rule_name)
            policy.create(self._harbor_client, project_name, image, registry)
            self._replication_policies[replication_rule_name] = policy
            logger.info(f"Created policy {replication_rule_name}")

        if self._trigger_replication_rule:
            policy.trigger_execution(self._harbor_client)
            logger.info(f"Triggered execution of policy {policy.name}")

        logger.info(f"Replication of {image} has been created")

    def remove_image_replication(self, image, delete_projects):
        logger.debug(f"Attempting to remove replication for {image}")

        replication_rule_name = self.create_replication_rule_name(image)
        try:
            policy = self._replication_policies[replication_rule_name]
            try:
                policy.tags.remove(image.tag)
            except KeyError:  # tag not in rule
                pass

            if policy.tags:
                policy.update_filters(self._harbor_client)
            else:  # no tags - delete rule
                policy.delete(self._harbor_client)
                logger.info(f"Removed policy {policy.name}")
                del self._replication_policies[replication_rule_name]
        except KeyError:
            logger.debug("policy %s does not exist" % replication_rule_name)

        if delete_projects:
            project_name = image.namespace
            try:
                project = self._projects[project_name]
                project.delete(self._harbor_client)
                logger.info(f"Removed project {project_name}")
                del self._projects[project_name]
            except KeyError as kerr:
                logger.debug(f"Received key error: {kerr}")
                logger.debug(f"Project {project_name!r} does not exist")

        logger.info(f"Removed replication of {image}")

    def create_replication_rule_name(self, image):
        rule_name = f"{image.namespace}-{image.name}"
        return self._replication_rule_prefix + rule_name


class HarborClient:
    def __init__(self, base_url, username, password, verify_certificate=True):
        if not base_url.startswith("http"):
            base_url = "https://" + base_url
        if not base_url.endswith("/"):
            base_url = base_url + "/"

        self.base_url = base_url
        self._credentials = HTTPBasicAuth(username, password)

        self._session = requests.Session()
        self._session.verify = verify_certificate

    def get(self, path):
        address = self.base_url + path

        response = self._session.get(address, auth=self._credentials)
        try:
            response.raise_for_status()
        except Exception as err:
            logger.debug(f"Request failed: {err}")
            logger.debug(f"Response headers: {response.headers}")
            logger.debug(f"Response body: {response.json()}")
            raise

        csrf_token = response.headers.get("X-Harbor-Csrf-Token")
        if csrf_token:
            self._session.headers.update({"X-Harbor-Csrf-Token": csrf_token})

        returned_elements = response.json()

        total_count = int(response.headers.get("X-Total-Count", 0))
        if not total_count or total_count == len(returned_elements):
            return returned_elements

        # Get all elements...
        elements = returned_elements

        def get_next_page():
            # 'Link': '</api/v2.0/projects?page=2&page_size=10>; rel="next"'
            try:
                next_page = response.headers["Link"]
            except KeyError:
                return None

            if "next" not in next_page:
                return None

            if next_page.count(";") >= 2:
                # Multiple references - usually pre and next
                for page in next_page.split(", "):
                    if "next" in page:
                        next_page = page
                        break

            next_page, _ = next_page.split(";")

            return next_page[1:-1]

        next_page = get_next_page()
        while next_page:
            response = self._session.get(
                f"{self.base_url}{next_page}", auth=self._credentials
            )
            elements.extend(response.json())
            next_page = get_next_page()

        logger.debug(f"Received elements {len(elements)}: {elements!r}")
        return elements

    def get_replication_policies(self):
        for policy in self.get("api/v2.0/replication/policies"):
            yield ReplicationPolicy.from_json(policy)

    def get_replication_policy_json(self, name):
        for policy in self.get_replication_policies():
            if policy.name == name:
                return policy._raw
        else:
            raise RuntimeError(f"No replication policy {name}")

    def create_replication_policy(self, name, config):
        address = self.base_url + "api/v2.0/replication/policies/"

        response = self._session.post(address, auth=self._credentials, json=config)
        try:
            response.raise_for_status()
        except Exception:
            logger.debug("Creating a replication policy failed.")
            logger.debug(f"Response headers: {response.headers}")
            raise

    def update_replication_policy(self, policy_id, config):
        address = self.base_url + f"api/v2.0/replication/policies/{policy_id}"

        response = self._session.put(address, auth=self._credentials, json=config)
        try:
            response.raise_for_status()
        except Exception:
            logger.debug("Updating a replication policy failed.")
            logger.debug(f"Response headers: {response.headers}")
            raise

    def delete_replication_policy(self, id):
        address = self.base_url + f"api/v2.0/replication/policies/{id}"
        response = self._session.delete(address, auth=self._credentials)
        response.raise_for_status()

    def trigger_replication_policy_execution(self, id):
        address = self.base_url + "api/v2.0/replication/executions/"

        response = self._session.post(
            address, auth=self._credentials, json={"policy_id": id}
        )
        try:
            response.raise_for_status()
        except Exception:
            logger.debug(f"Triggering replication for rule #{id} failed.")
            logger.debug(f"Headers: {response.headers}")
            raise

    def get_projects(self):
        for project in self.get("api/v2.0/projects"):
            yield HarborProject.from_json(project)

    def get_project_json(self, name_or_id):
        project = self.get(f"api/v2.0/projects/{name_or_id}")

        if not project:
            raise RuntimeError(f"No project {name_or_id}")

        return project

    def create_project(self, name, config):
        address = self.base_url + "api/v2.0/projects"

        response = self._session.post(address, auth=self._credentials, json=config)
        logger.debug(f"Response headers: {response.headers}")
        logger.debug(f"Response body: {response.content}")
        response.raise_for_status()

        try:
            return response.json()
        except json.decoder.JSONDecodeError:
            return None

    def is_project_deletable(self, name_or_id):
        response = self.get(f"api/v2.0/projects/{name_or_id}/_deletable")
        logger.debug(f"Deletable for {name_or_id}: {response}")

        try:
            return response["deletable"]
        except KeyError:
            try:
                logger.debug(response["message"])
            except KeyError:  # no message
                pass

            return False

    def remove_project_content(self, name):
        repos = self.get(f"api/v2.0/projects/{name}/repositories")

        for repo in repos:
            logger.debug(f"Repo: {repo!r}")
            repo_name = repo["name"]

            if repo_name.startswith(name + "/"):
                repo_name = repo_name[len(name) + 1 :]

            if "/" in repo_name:
                # Double URL encoded
                repo_name = quote(quote(repo_name, safe=""))

            logger.debug(f"Deleting repository {repo_name} in {name}")
            address = (
                self.base_url + f"api/v2.0/projects/{name}/repositories/{repo_name}"
            )
            response = self._session.delete(address, auth=self._credentials)
            logger.debug(f"Response headers: {response.headers}")
            response.raise_for_status()

    def delete_project(self, name_or_id):
        address = self.base_url + f"api/v2.0/projects/{name_or_id}"
        response = self._session.delete(
            address, auth=self._credentials, headers={"X-Is-Resource-Name": "true"}
        )
        response.raise_for_status()

    def get_registry(self, name):
        registries = self.get("api/v2.0/registries")
        registry_names = set()
        for registry in registries:
            registry_name = registry["name"]
            registry_names.add(registry_name)
            if registry_name == name:
                return registry

        logger.info("Available registries: {}".format(", ".join(registry_names)))

        raise ValueError(f"No registry {name!r} found")


if __name__ == "__main__":
    main()
