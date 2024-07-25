# Fuzzor

## Usage

At the moment, fuzzor consists of two utilities: `fuzz-project` and `fuzz-prs`.

`fuzz-project` can be used to continuously fuzz a single project. It monitors
for source code changes on the configure repo and if a new revision is
detected, it will kick of a new build and subsequent fuzzing campaigns.

All harnesses are fuzzed in a round-robin fashion, unless a new revision was
build, in which case new harnesses and the harnesses that reach the recently
modified code are prioritized.

```
Usage: fuzz-project [OPTIONS] --project <PROJECT>

Options:
      --project <PROJECT>
          Project to fuzz
      --owner <OWNER>
          Overwrite the repo owner from the config
      --repo <REPO>
          Overwrite the repo from the config
      --branch <BRANCH>
          Overwrite the branch from the config
      --name <NAME>
          Overwrite the name from the config
      --harnesses <HARNESSES>
          Specify the list of harnesses to fuzz
      --cores-per-build <CORES_PER_BUILD>
          Number of cores to use for builds [default: 16]
      --cores-per-campaign <CORES_PER_CAMPAIGN>
          Number of cores to use for each campaign [default: 16]
      --campaign-duration <CAMPAIGN_DURATION>
          Campaign duration in CPU hours [default: 16]
  -h, --help
          Print help
```

`fuzz-prs` enables fuzzing pull requests of a given project. It tries to fuzz
any newly introduced harnesses by a given PR, as well as harnesses that are
able to reach the modified code.

For it to work properly, all harnesses in the base project should have been
fuzzed with `fuzz-project` (this makes sure that fuzzor has the required
context for coverage based harness scheduling).

```
Usage: fuzz-prs [OPTIONS] --project <PROJECT> --prs <PULL_REQUESTS>

Options:
      --project <PROJECT>
          Project to fuzz
      --prs <PULL_REQUESTS>
          Specify the list of PRs to fuzz
      --cores-per-build <CORES_PER_BUILD>
          Number of cores to use for builds [default: 16]
      --cores-per-campaign <CORES_PER_CAMPAIGN>
          Number of cores to use for each campaign [default: 16]
      --campaign-duration <CAMPAIGN_DURATION>
          Campaign duration in CPU hours [default: 16]
      --base-campaign-duration <BASE_CAMPAIGN_DURATION>
          Campaign duration in CPU hours for the base project [default: 16]
  -h, --help
          Print help
```

### Project Integration

### Required: Building the Base Image

The project specific docker images (e.g. `projects/bitcoin/Docker`) all build
on top of the `fuzzor-base` image, which can be build from the docker file in
`infra/Dockerfile.base`:

```
docker build --tag fuzzor-base:latest --file Dockerfile.base .
```

### Environment vars

- `FUZZOR_KILL_TIMEOUT`: How long to wait before killing a container when trying to stop it gracefully (in seconds)
- `FUZZOR_GH_TRACK_INTERVAL`: Interval between GitHub API queries for repo events (in seconds)
- `FUZZOR_CAMPAIGN_INTERVAL`: Interval campaign status inspections (in seconds)
- `FUZZOR_DOCKER_NOCACHE`: Set to disable docker build cache
- `FUZZOR_DONT_REMOVE_CONTAINERS`: Set to disable the removal of campaign containers
- `FUZZOR_GH_TOKEN`: GitHub access token for accesing public repos and reporting solutions

### Docker base image build args

- `FUZZOR_CI`: Limit resources needed to build the envs for e.g. CI runs
