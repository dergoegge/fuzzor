### Environment vars

- `FUZZOR_KILL_TIMEOUT`: How long to wait before killing a container when trying to stop it gracefully (in seconds)
- `FUZZOR_GH_TRACK_INTERVAL`: Interval between GitHub API queries for repo events (in seconds)
- `FUZZOR_CAMPAIGN_INTERVAL`: Interval campaign status inspections (in seconds)
- `FUZZOR_DOCKER_NOCACHE`: Set to disable docker build cache
- `FUZZOR_DONT_REMOVE_CONTAINERS`: Set to disable the removal of campaign containers
- `FUZZOR_GH_TOKEN`: GitHub access token for accesing public repos and reporting solutions

### Docker base image build args

- `FUZZOR_CI`: Limit resources needed to build the envs for e.g. CI runs
