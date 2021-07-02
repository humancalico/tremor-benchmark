use clap::{crate_authors, crate_version, Clap};
use color_eyre::eyre::Result;
use dotenv::dotenv;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use tremor_benchmark::{convert_into_relevant_data, deserialize, serialize, update_json};

#[derive(Clap)]
#[clap(version = crate_version!(), author = crate_authors!())]
struct Opts {
    /// Path to the JSON file where your benchmark data is stored
    data_file: PathBuf,
    /// Path to the JSON file where the last benchmark data is to be stored
    recent_file: PathBuf,
    /// SHA256 of the commit you want to benchmark
    commit_hash: String,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    // TODO check for dependencies like docker, docker-compose and git
    // TODO should be able to use other container runtimes other than docker compose like podman

    dotenv().ok();

    let opts: Opts = Opts::parse();

    // calculate short commit hash
    let short_commit_hash = &opts.commit_hash[..6];

    let original_working_directory = env::current_dir()?;

    // change the directory to docker/
    // How do I do this? Since I have no idea where my binary would run from. I can assume it runs
    // from the root of the project since that is the most likely scenario but that's not ideal
    env::set_current_dir(original_working_directory.join("docker")).expect("failed to change the current directory to docker/. Are you running this program from the root directory");

    // build Docker Image
    // FIXME this assumes that this process is run from the docker/ directory
    fs::write("Dockerfile", String::from(
    r#"FROM rust:1.53 as builder

# TODO ensure wget is present
# TODO figure out a way to get commit hash here
# We planned to disable networking inside the docker container at first but now we are doing this so that
# can't be done anymore
# TODO figure out a way by which we can allow networking in docker for certain sites only
RUN wget https://github.com/tremor-rs/tremor-runtime/archive/COMMITHASH.tar.gz

RUN tar -xf COMMITHASH.tar.gz

RUN rm COMMITHASH.tar.gz

WORKDIR tremor-runtime-COMMITHASH/

ENV RUSTFLAGS="-C target-feature=+avx,+avx2,+sse4.2"

# install dependencies
RUN apt-get update \
    && apt-get install -y libclang-dev cmake

RUN cargo build -p tremor-cli --release

FROM debian:buster-slim

RUN useradd -ms /bin/bash tremor

RUN apt-get update \
    && apt-get install -y libssl1.1 libcurl4 libatomic1 tini curl

# Copy the binary to /usr/local/bin
COPY --from=builder tremor-runtime-COMMITHASH/target/release/tremor /usr/local/bin/

# stdlib
RUN mkdir -p /usr/share/tremor/lib
COPY --from=builder tremor-runtime-COMMITHASH/tremor-script/lib /usr/share/tremor/lib

# setting TREMOR_PATH
# /usr/local/share/tremor - for host-specific local tremor-script modules and libraries, takes precedence
# /usr/share/tremor/lib - place for the tremor-script stdlib
ENV TREMOR_PATH="/usr/local/share/tremor:/usr/share/tremor/lib"

RUN cd ..

COPY benchmarks/ .

CMD [ "tremor", "test", "bench", "/bench", "-o" ]
"#).replace("COMMITHASH", &opts.commit_hash))?;

    // add the commit hash as tag
    Command::new("docker")
        .args(&[
            "build",
            ".",
            "-t",
            &format!("tremor-benchmark:{}", short_commit_hash),
        ])
        .output()?;

    // create a report.json file
    // CAVEAT this file can only be created inside the docker/ directory because of our
    // docker-compose.yml
    fs::File::create("report.json")?;
    let report_path = Path::new("report.json").canonicalize()?;

    // write a docker-compose.yml file
    // TODO read the docker-compose.yml file to string
    // TODO use the docker copy command to copy the report.json file instead of doing this
    fs::write(
        "docker-compose.yml",
        format!(
            r#"version: '3.8'

services:
  benchmark:
    image: tremor-benchmark:{}
    build: .
    volumes:
      - ./report.json:/report.json
    container_name: tremor-benchmark-compose
"#,
            short_commit_hash
        ),
    )?;

    // TODO add some sort of a timeout

    // run benchmarks inside docker image and store it in a report.json
    Command::new("docker-compose").arg("up").output()?;

    // change the directory back
    env::set_current_dir(&original_working_directory)?;

    Command::new("git")
        .args(&[
            "clone",
            "--depth=1",
            "branch",
            "data",
            &format!(
                "https://{}@github.com/tremor-rs/tremor-benchmark.git",
                env::var("TREMORBOT_PAT")?
            ),
            "data",
        ])
        .output()?;

    // parse the report into data.json and recent.json
    fs::write(
        &opts.recent_file,
        serialize(&convert_into_relevant_data(
            deserialize(&fs::read_to_string(report_path)?)?,
            &opts.commit_hash,
        )?)?,
    )?;

    fs::write(
        &opts.data_file,
        update_json(
            &fs::read_to_string(&opts.data_file)?,
            &fs::read_to_string(opts.recent_file)?,
        ),
    )?;

    // remove Dockefile
    fs::remove_file(Path::new("docker").join("Dockerfile"))?;

    // remove report.json file
    fs::remove_file(Path::new("docker").join("report.json"))?;

    // remove docker-compose.yml
    fs::remove_file(Path::new("docker").join("docker-compose.yml"))?;

    // remove everything docker
    // FIXME this is probably very bad
    Command::new("docker")
        .args(&["system", "prune", "--all"])
        .output()?;

    // git config user.email 81628356+tremorbot@users.noreply.github.com
    Command::new("git")
        .args(&[
            "config",
            "user.email",
            "81628356+tremorbot@users.noreply.github.com",
        ])
        .output()?;

    // git config user.name "tremorbot"
    Command::new("git")
        .args(&["config", "user.name", "tremorbot"])
        .output()?;

    env::set_current_dir("data")
        .expect("failed to change the current directory to tremor-benchmark");

    // git add data/data.json data/recent.json
    Command::new("git")
        .args(&["add", "data.json", "recent.json"])
        .output()?;

    // git commit --message "chore(data): update benchmarks for SHORTCOMMITHASH"
    Command::new("git")
        .args(&[
            "commit",
            "-m",
            &format!("chore(data): update benchmarks for {}", short_commit_hash),
        ])
        .output()?;

    // git push
    Command::new("git").args("push").output()?;

    env::set_current_dir("..")?;

    fs::remove_dir_all("data")?;

    Ok(())
}
