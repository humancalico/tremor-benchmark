/*
 * Verify GitHub webhook signature header in Node.js
 * Written by stigok and others (see gist link for contributor comments)
 * https://gist.github.com/stigok/57d075c1cf2a609cb758898c0b202428
 * Licensed CC0 1.0 Universal
 */
const { spawnSync } = require("child_process");
const crypto = require("crypto");

const express = require("express");
require("dotenv").config();

const app = express();

app.use(express.json({
  verify: (req, res, buf, encoding) => {
    if (buf && buf.length) {
      req.rawBody = buf.toString(encoding || "utf8");
    }
  },
}));

const sigHeaderName = "X-Hub-Signature-256";
const sigHashAlg = "sha256";

function verify(req, res, next) {
  if (!req.rawBody) {
    return next("Request body empty");
  }
  const sig = Buffer.from(req.get(sigHeaderName) || "", "utf8");
  const hmac = crypto.createHmac(sigHashAlg, process.env.SECRET);
  const digest = Buffer.from(
    sigHashAlg + "=" + hmac.update(req.rawBody).digest("hex"),
    "utf8",
  );
  if (sig.length !== digest.length || !crypto.timingSafeEqual(digest, sig)) {
    return next(
      `Request body digest (${digest}) did not match ${sigHeaderName} (${sig})`,
    );
  }

  next();
}

app.post("/payload", verify, function (req, res) {
  // TODO change check_suite to check_run
  let commit_hash;
  if (
    req.body.action === "completed" &&
    req.body.check_suite.conclusion === "success" &&
    req.body.check_suite.head_branch === "main" &&
    // FIXME here(https://docs.github.com/en/developers/webhooks-and-events/webhooks/webhook-events-and-payloads#check_suite)
    // it says that > The Checks API only looks for pushes in the repository where the check suite or check run were created. Pushes to a branch in a forked repository are not detected and return an empty pull_requests array and a null value for head_branch.
    // But it still sends the payload for pull_requests even after adding this check
    req.body.check_suite.pull_requests.length === 0 &&
    commit_hash !== req.body.check_suite.head_sha
  ) {
    console.log(req.body);
    commit_hash = req.body.check_suite.head_sha;
    // respond to the post request
    res.status(200).send(
      `Received a request for the commit ${commit_hash} and request body was signed`,
    );
    // start the benchmark pipeline
    const child = spawnSync("./target/release/tremor-benchmark", [
      "./data/data.json",
      "./data/recent.json",
      commit_hash,
    ], { encoding: "utf8" });

    if (child.error) {
      console.log("ERROR: ", child.error);
    }
    console.log("stdout: ", child.stdout);
    console.log("stderr: ", child.stderr);
    console.log("exit code: ", child.status);
  }
});

app.use((err, req, res, next) => {
  if (err) console.error(err);
  res.status(403).send("Request body was not signed or verification failed");
});

// should this be hardcoded?
const port = 9247;
const address = "0.0.0.0";
app.listen(
  port,
  address,
  () => console.log(`Listening on port ${address}:${port}`),
);
