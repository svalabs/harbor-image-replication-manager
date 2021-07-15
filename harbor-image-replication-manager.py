import argparse
import time
from collections import namedtuple

import requests
from requests.auth import HTTPBasicAuth


Image = namedtuple('Image', 'namespace name tag')


def main():
    options = parse_cli()

    images = get_images(options.imagefile)

    h = HarborClient(options.base_url, options.username, options.password, options.verify_cert)
    manager = HarborManager(h, replication_rule_prefix=options.rule_prefix)

    if options.mode == 'create':
        process_func = manager.replicate_image
    elif options.mode == 'delete':
        process_func = manager.remove_image_replication
    else:
        raise RuntimeError(f"Invalid mode: {options.mode!r}")

    for image in images:
        process_func(image)


def parse_cli():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image-file', '-i', dest='imagefile', required=True)
    parser.add_argument('--rule-prefix', dest='rule_prefix', default='hir-', help="The prefix for managed policies")
    parser.add_argument('--no-rule-trigger', dest='trigger', action="store_false", help="Trigger replication for policies")
    parser.add_argument('mode', choices=['create', 'delete'])

    harbor = parser.add_argument_group('Harbor', description="Configuration for the connection to Harbor")
    harbor.add_argument('--harbor', default="registry.labda.sva.de", help="Harbor address")
    harbor.add_argument('--user', dest="username", required=True, help="Username to use")
    harbor.add_argument('--password', dest="password", required=True, help="Password to use")
    harbor.add_argument('--insecure', action='store_false', dest='verify_cert', help="Do not verify server certificates")

    return parser.parse_args()


def get_images(image_file):
    with open(image_file) as imagefile:
        images = imagefile.readlines()

    return [split_image_line(image) for image in images]


def split_image_line(line):
    line = line.strip()
    try:
        namespace, image_and_tag = line.split('/', 1)
    except ValueError:
        namespace = 'library'
        image_and_tag = line

    try:
        image, tag = image_and_tag.split(':', 1)
    except ValueError:
        image = image_and_tag
        tag = None

    return Image(namespace, image, tag)


class HarborProject:
    def __init__(self, name, *, raw=None):
        self.name = name
        self._raw = raw or None

    def create(self, harbor_client):
        data = {
          "project_name": self.name,
          "registry_id": 0,
          "public": True,
          "storage_limit": 0,
        }

        try:
            harbor_client.create_project(self.name, data)
        except RepoExistsError:
            print(f"Repo {self.name} exists")

        self._raw = harbor_client.get_project_json(self.name)

    def delete(self, harbor_client):
        if not self._raw:
            return

        # TODO: remove repositories in project
        # TODO: ask if we want to remove the repos from the project

        harbor_client.delete_project(self.name)

    def exists(self):
        return bool(self._raw)

    @classmethod
    def from_json(cls, project_json):
        # {'chart_count': 0,
        #  'creation_time': '2020-08-25T09:47:47.000Z',
        #  'current_user_role_id': 1,
        #  'current_user_role_ids': [1],
        #  'cve_allowlist': {'creation_time': '0001-01-01T00:00:00.000Z', 'id': 1, 'items': [], 'project_id': 34, 'update_time': '0001-01-01T00:00:00.000Z'},
        #  'metadata': {'public': 'true'},
        # 'name': 'alpine',
        # 'owner_id': 1,
        # 'owner_name': 'admin',
        # 'project_id': 34,
        # 'repo_count': 9,
        # 'update_time': '2020-08-25T09:47:47.000Z'}
        return HarborProject(project_json['name'], raw=project_json)


class ReplicationPolicy:
    def __init__(self, name, *, raw=None):
        self.name = name
        self._raw = raw or None

    @property
    def id(self):
        try:
            return self._raw['id']
        except TypeError:
            raise RuntimeError("Policy not created on harbor.")

    def create(self, harbor_client, project_name, image):
        tag = image.tag or '**'

        name = f"{image.namespace}/{image.name}"
        data = {
              "description": f"Managed by {__file__}",
              "dest_namespace_replace_count": 0,  # flattening  # TODO: what level?
              "filters": [
                {'type': 'name', 'value': name},
                {'type': 'tag', 'value': tag}
                ],
              "dest_registry": {'creation_time': '0001-01-01T00:00:00.000Z', 'credential': {'access_secret': '*****', 'type': 'secret'}, 'id': 0, 'insecure': True, 'name': 'Local', 'type': 'harbor', 'update_time': '0001-01-01T00:00:00.000Z', 'url': 'http://core:8080'},
              "src_registry": {'creation_time': '2020-11-09T12:50:46.339Z', 'credential': {'access_key': 'cfey', 'access_secret': '*****', 'type': 'basic'}, 'id': 2, 'name': 'dockerhub-proxy', 'status': 'healthy', 'type': 'docker-hub', 'update_time': '2021-07-12T14:41:33.679Z', 'url': 'https://hub.docker.com'},
              "dest_namespace": project_name,
              "trigger": {'trigger_settings': {}, 'type': 'manual'},
              "replicate_deletion": True,
              "deletion": True,
              "override": True,
              "enabled": True,
              "name": self.name
            }

        harbor_client.create_replication_policy(self.name, data)

        time.sleep(30)
        self._raw = harbor_client.get_replication_policy_json(self.name)

    def trigger_execution(self, harbor_client):
        harbor_client.trigger_replication_policy_execution(self.id)

    def delete(self, harbor_client):
        if not self._raw:
            return

        harbor_client.delete_replication_policy(self.id)

    def exists(self):
        return bool(self._raw)

    def __repr__(self):
        return '<ReplicationPolicy(name=%s)>' % self.name

    @classmethod
    def from_json(cls, policy_json):
        # {'creation_time': '2021-07-14T11:23:12.534Z',
        # 'description': 'Testing Rancher Image Replication',
        # 'dest_namespace': 'nwenselo-rancher',
        # 'dest_namespace_replace_count': 1,
        # 'dest_registry': {'creation_time': '0001-01-01T00:00:00.000Z', 'credential': {'access_secret': '*****', 'type': 'secret'}, 'id': 0, 'insecure': True, 'name': 'Local', 'status': 'healthy', 'type': 'harbor', 'update_time': '0001-01-01T00:00:00.000Z', 'url': 'http://core:8080'},
        # 'enabled': True,
        # 'filters': [{'type': 'name', 'value': 'rancher/*'}, {'type': 'tag', 'value': '**'}],
        # 'id': 3,
        # 'name': 'nwe-rancher-images',
        # 'override': True,
        # 'src_registry': {'creation_time': '2020-11-09T12:50:46.339Z', 'credential': {'access_key': 'cfey', 'access_secret': '*****', 'type': 'basic'}, 'id': 2, 'name': 'dockerhub-proxy', 'status': 'healthy', 'type': 'docker-hub', 'update_time': '2021-07-12T14:41:33.679Z', 'url': 'https://hub.docker.com'},
        # 'trigger': {'trigger_settings': {}, 'type': 'manual'},
        # 'update_time': '2021-07-14T11:31:59.023Z'}
        return ReplicationPolicy(policy_json['name'], raw=policy_json)


class HarborManager:
    def __init__(self, harbor_client, *, replication_rule_prefix):
        self._harbor_client = harbor_client
        self._replication_rule_prefix = replication_rule_prefix

        self._replication_policies = {policy.name: policy for policy in self._harbor_client.get_replication_policies()}
        self._projects = {project.name: project for project in self._harbor_client.get_projects()}

    def replicate_image(self, image):
        print(f"Attempting to replicate {image}")

        project_name = image.namespace
        try:
            project = self._projects[project_name]
        except KeyError:
            # TODO: remove try/catch
            try:
                print(f"Creating project {project_name}")
                project = HarborProject(project_name)
                project.create(self._harbor_client)
                self._projects[project_name] = project
                print(f"Created project {project.name}")
            except Exception as err:
                print(f"Failed to create project: {err}")

        replication_rule_name = self.create_replication_rule_name(image)
        try:
            policy = self._replication_policies[replication_rule_name]
        except KeyError:
            print("policy %s does not exist" % replication_rule_name)
            policy = ReplicationPolicy(replication_rule_name)
            policy.create(self._harbor_client, project.name, image)
            print(f"Created policy {replication_rule_name}")

        # TODO: only trigger if param is given
        policy.trigger_execution(self._harbor_client)
        print(f"Triggered execution of policy {policy.name}")

        # TODO: Handle adding new tags

        print(f"Replicating {image}")

    def remove_image_replication(self, image):
        print(f"Attempting to remove replication for {image}")

        replication_rule_name = self.create_replication_rule_name(image)
        try:
            policy = self._replication_policies[replication_rule_name]
            policy.delete(self._harbor_client)
            print(f"Removed policy {policy.name}")
        except KeyError:
            print("policy %s does not exist" % replication_rule_name)

        project_name = image.namespace
        try:
            project = self._projects[project_name]
            project.delete(self._harbor_client)
            print(f"Removed project {project.name}")
        except KeyError:
            print("Project %s does not exist" % project_name)

        print(f"Removed replication of {image}")

    def create_replication_rule_name(self, image):
        rule_name = f'{image.namespace}-{image.name}'
        return self._replication_rule_prefix + rule_name


class HarborClient:
    def __init__(self, base_url, username, password, verify_certificate=True):
        if not base_url.startswith('http'):
            base_url = 'https://' + base_url
        if not base_url.endswith('/'):
            base_url = base_url + '/'

        self.base_url = base_url
        self._credentials = HTTPBasicAuth(username, password)

        self._session = requests.Session()
        self._session.verify = verify_certificate

    def get(self, path):
        address = self.base_url + path

        response = self._session.get(address, auth=self._credentials)
        try:
            response.raise_for_status()
        except Exception:
            print(response.headers)
            print(response.json())
            raise

        csrf_token = response.headers.get('X-Harbor-Csrf-Token')
        if csrf_token:
            self._session.headers.update({'X-Harbor-Csrf-Token': csrf_token})

        returned_elements = response.json()

        total_count = int(response.headers.get('X-Total-Count', 0))
        if not total_count or total_count == len(returned_elements):
            return returned_elements

        # Get all elements...
        elements = returned_elements

        def get_next_page():
            # 'Link': '</api/v2.0/projects?page=2&page_size=10>; rel="next"'
            try:
                next_page = response.headers['Link']
            except KeyError:
                return None

            if 'next' not in next_page:
                return None

            next_page, _ = next_page.split(';')

            return next_page[1:-1]

        next_page = get_next_page()
        while next_page:
            response = self._session.get(f"{self.base_url}{next_page}", auth=self._credentials)
            elements.extend(response.json())
            next_page = get_next_page()

        print(f"elements {len(elements)}: {elements}")
        return elements

    def get_replication_policies(self):
        for policy in self.get('api/v2.0/replication/policies'):
            yield ReplicationPolicy.from_json(policy)

    def get_replication_policy_json(self, name):
        for policy in self.get_replication_policies():
            if policy.name == name:
                return policy
        else:
            raise RuntimeError(f"No replication policy {name}")

    def create_replication_policy(self, name, config):
        address = self.base_url + f'api/v2.0/replication/policies/'

        response = self._session.post(address, auth=self._credentials, json=config)
        try:
            response.raise_for_status()
        except Exception:
            print(response.headers)
            raise

    def delete_replication_policy(self, id):
        address = self.base_url + f'api/v2.0/replication/policies/{id}'
        response = self._session.delete(address, auth=self._credentials)
        response.raise_for_status()

    def trigger_replication_policy_execution(self, id):
        address = self.base_url + f'api/v2.0/replication/executions/'

        response = self._session.post(address, auth=self._credentials, json={"policy_id": id})
        try:
            response.raise_for_status()
        except Exception:
            print(response.headers)
            raise

    def get_projects(self):
        for project in self.get('api/v2.0/projects'):
            yield HarborProject.from_json(project)

    def get_project_json(self, name_or_id):
        project = self.get(f'api/v2.0/projects/{name_or_id}')

        if not project:
            raise RuntimeError(f"No project {name_or_id}")

        return project

    def create_project(self, name, config):
        address = self.base_url + 'api/v2.0/projects'

        response = self._session.head(address, auth=self._credentials, json={"project_name": name})
        try:
            response.raise_for_status()
        except Exception:
            raise RepoExistsError(f"Project {name} already exists")

        response = self._session.post(address, auth=self._credentials, json=config)
        response.raise_for_status()
        return response.json()

    def delete_project(self, name_or_id):
        address = self.base_url + f'api/v2.0/projects/{name_or_id}'
        response = self._session.delete(address, auth=self._credentials, headers={"X-Is-Resource-Name": "true"})
        response.raise_for_status()


class RepoExistsError(RuntimeError):
    pass


if __name__ == '__main__':
    main()
