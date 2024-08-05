# Contributing to Witness

We welcome contributions from the community and first want to thank you for
taking the time to contribute!

Before starting, please take some time to familiarize yourself with the [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

We welcome many different types of contributions and not all of them need a
Pull Request. Contributions may include:

* New features and proposals
* Documentation
* Bug fixes
* Issue Triage
* Answering questions and giving feedback
* Helping to onboard new contributors
* Other related activities

### Setting up your environment

### Required Tooling
Some tools are required on your system in order to help you with
the development process:

* Git: Witness is hosted on GitHub, so you will need to have Git installed. For
 more information, please follow [this guide](https://github.com/git-guides/install-git).

* GNU Make: The root of the directory contains a `Makefile` for automating development
 processes. The `make` CLI tool is usually installed by default on most systems
 (excluding Windows), but you can check if it is installed by running `make --version`
 on your terminal. If this command is unsuccessful, you will need to find the standard
 method for installing it for your system. For installing `make` on Windows, please see
 [here](https://gnuwin32.sourceforge.net/packages/make.htm).
 
* Go v1.19: Witness is written in [Go](https://golang.org/), so you 
 will need this installed in order to compile and run the source code.

#### Getting the Witness source code

[Fork](https://docs.github.com/en/get-started/quickstart/fork-a-repo) the repository on GitHub and
[clone](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository) it to
your local machine: 
```console
    git clone git@github.com:YOUR-USERNAME/witness.git
```
*The command above uses SSH to clone the repository, which we recommend. You can find out more
about how to set SSH up with Github [here](https://docs.github.com/en/authentication/connecting-to-github-with-ssh).*


Add a [remote](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/configuring-a-remote-repository-for-a-fork) and
regularly [sync](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/syncing-a-fork) to make sure
you stay up-to-date with our repository:

```console
    git remote add upstream https://github.com/in-toto/witness.git
    git checkout main
    git fetch upstream
    git merge upstream/main
```

### Running Tests

You can run all the tests by executing the command:

```console
    make test
```
