# Harbor Image Replication Manager

This tool allows you to manage [Harbor Replication Rules](https://goharbor.io/docs/edge/administration/configuring-replication/) and [Projects](https://goharbor.io/docs/edge/working-with-projects/) in order to achieve replication of a limited list of images with only their required tags.

This allows you to operate your own [Harbor](https://goharbor.io/) registry to act as a substitute to Docker Hub or other widely used registries.


## Image List Format

The image list should be a file where each line defines one image.

An example could look like the following:
```
busybox
rancher/k3s-upgrade:v1.19.10-k3s1
rancher/k3s-upgrade:v1.20.6-k3s1
registry:2
```

Images without a given namespace will be treated with the namespace _library_.
Images without a tag will be treated as _latest_.


## Requirements

This tool requires Python 3.6 or newer.
It requires the Python package `requests`.

You can install the requirements through `pip`:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage requires information on how to connect to your Harbor instance.
The supplied user must be able to manage replication rules and projects.

Each replication rule will get a prefix and a name based on namespace and image.
The prefix can be overriden through `--rule-prefix`.

### Setting up replication

For setting up replication use the `create` mode.
You will have to specify the registry used for the replication rule through their name.

```bash
python harbor-image-replication.py --image-file rancher-images.txt --harbor my.registry.domain.lan --registry "dockerhub" --user flamingo --password pink12 create
```

Missing projects will be created. They are public by default.

If a replication rule for an image already exists it will be expanded with the new tag.

After processing a replication rule the replication will be triggered once.

### Removing replication

The script is able to reverse the changes it made with the `delete` mode:

```bash
python harbor-image-replication.py --image-file rancher-images.txt --harbor my.registry.domain.lan --user flamingo --password pink12 delete
```

If a replication rule has multiple tags given only the tags from the given image file will be removed.
Only if a replication rule has only one remaining tag the image will be removed.

To also remove the involved projects you can supply `--delete-projects`. This will empty the project before removing it.
