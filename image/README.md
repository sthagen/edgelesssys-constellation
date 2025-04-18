## Setup

Ensure you have Nix installed. This is a requirement for the following steps.
Consult the [developer docs](/dev-docs/workflows/build-develop-deploy.md) for more info.
At the very least, `nix` should be in your PATH.

Building the image also requires `newuidmap` and `newgidmap` to be present in the PATH. On Debian and Ubuntu, these can be sourced through
the `uidmap` package.

## Build

You can build any image using Bazel.
Start by querying the available images:

```sh
bazel query //image/system/...
```

You can either build a group of images (all images for a cloud provider, a stream, ...) or a single image by selecting a target.

```sh
bazel build //image/system:azure_azure-sev-snp_stable
```

The location of the destination folder can be queried like this:

```sh
bazel cquery --output=files //image/system:azure_azure-sev-snp_stable
```

## Build and Upload

Similarly, you can also build and upload images to the respective CSP within a single step with the `upload_*` targets.

```sh
bazel run //image/system:upload_aws_aws-sev-snp_console -- --ref deps-image-fedora-40 --upload-measurements
```

The `--ref` should be the branch you're building images on. It should **not contain slashes**. Slashes should be replaced with dashes to
not break the filesystem structure of the image storages.

Optionally, the `--upload-measurements` option can be used to specify that measurements for the image should be uploaded, and `--fake-sign` specifies
that a debugging signing key should be used to sign the measurements, which is done for debug images.

## Kernel

The Kernel is built from the srpm published under [edgelesssys/constellation-kernel](https://github.com/edgelesssys/constellation-kernel).
We track the latest longterm release, use sources directly from [kernel.org](https://www.kernel.org/) and build the Kernel using the steps specified in the
srpm spec file.

After building a Kernel rpm, we upload it to our CDN and use it in our image builds.

## Upgrading to a new Fedora release

- Search for the old Fedora releasever in the `image/` directory and replace every occurence (outside of lockfiles) with the new releasever
- Search for Fedora container images in Dockerfiles and upgrade the releasever
- Regenerate the package lockfile: `bazel run //image/mirror:update_packages`
- Build test images locally:
  - `bazel query //image/system:all` (pick an image name from the output)
  - `bazel build //image/system:IMAGE_NAME_HERE` (replace with an actual image name)
- Let CI build new images and run e2e tests
- Upgrade kernel spec under [edgelesssys/constellation-kernel](https://github.com/edgelesssys/constellation-kernel) to use new releasever

## Adding new packages to the image

- Find the package (i.e. it's _package name_) on [Koji](https://koji.fedoraproject.org/koji/)
- Add the package to the corresponding section in `./base/mkosi.conf`
  - If the package is required to be present in the initrd, add it to `./initrd/mkosi.conf`
- Add the package to `./mirror/packages.txt`
- Update the package mirror:
  ```sh
  bazel run //image/mirror:update_packages
  ```
- Build new images (e.g. via CI) and run e2e tests
