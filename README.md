# Harbor Image Replication Manager

This tool allows you to manage Harbor Replication Policies and Projects in order to achieve replication of a limited list of images.

This allows you to operate your own registry to act as a substitute to docker hub.


## Image List Format

The image list should be a file where each line defines one image.

An example could look like the following:
```
busybox
rancher/k3s-upgrade:v1.19.10-k3s1
rancher/k3s-upgrade:v1.20.6-k3s1
registry:2
```

Images without a namespace will be treated with the namespace `library`.
Images without a tag will be treated as _latest_.


## Requirements

This tool requires Python 3.6 or newer.
It requires the Python package `requests`.

You can install the requirements through `pip`:
```bash
pip install -r requirements.txt
```

## Usage

```bash
python harbor-image-replication.py --image-file rancher-images.txt --harbor my.registry.domain.lan --user flamingo --password pink12 create
```
