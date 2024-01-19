# Contributing

We welcome any and all contributions to Witness! If you are interested in contributing there are a few guidelines we ask
that you follow.

## Finding an issue to work on

We maintain our backlog and list of work in Github issues.  Issues are a good place to start to find a way to contribute
as maintainers actively groom the backlog.  If you have an issue that is not in the Github issues for the project feel
free to create an issue.  Please comment on an issue to let others know that you are working on it.

## Committing

The Witness maintainers have chosen to adopt the [Coventional Commit](https://www.conventionalcommits.org/en/v1.0.0/)
specification for commit messages.  Please read and familiarize yourself with the specification in preparation for your
work to be brought upstream.

We also ask that you sign-off your commits.  By signing off you agree to the
[Developer Certificate of Origin](https://developercertificate.org):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.

```

Each commit should be a meaningful body of work.  This typically means a pull request will consist of a singular commit
but there are cases where multiple commits per pull request is warranted.  It is okay to make small multiple commits
while going through the review process but you will be asked to rebase your commits as the final step of a pull request.
If you are uncomfortable with rebasing please ask a maintainer to help out or rebase for you.

Commit messages should begin with a short description that fits within about 80 characters.  The body of the commit
should be descriptive about what is being done in your commit.

Tests should be written whenever possible.

## Opening a Pull Request

Once you're ready for your code to be reviewed you can open a pull request.  Draft pull requests are also welcome for
works in progress.  Each pull request should link to the issue that is being addressed.  All CI processes are required
to pass and a maintainer's approval is required for pull requests to be upstreamed.

Maintainers may request changes and ask questions during the review process.  We seek to maintain a welcoming
collaborative environment.  Please see CODE_OF_CONDUCT.md in the project's root for the code of conduct.  Reviews and
change requests are always to be constructive.  If you have questions or concerns during the review process feel free to
reach out at [community@testifysec.com](mailto:community@testifysec.com).
=======
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
 [here](https://gnuwin32.sourceforge.net/packages/make.html).
 
* Go v1.19: Witness is written in [Go](https://golang.org/), so you 
 will need this installed in order to compile and run the source code.

#### Getting the Witness source code

[Fork](https://docs.github.com/en/get-started/quickstart/fork-a-repo>) the repository on GitHub and
[clone](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository) it to
your local machine: 
```console
    git clone git@github.com:YOUR-USERNAME/witness.git
```
*The command above uses SSH to clone the repository, which we recommend. You can find out more
about how to set SSH up with Github [here](https://docs.github.com/en/authentication/connecting-to-github-with-ssh).*


Add a [remote](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/configuring-a-remote-for-a-fork) and
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
