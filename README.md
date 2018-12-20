# Container Security Vulnerability Summarization Tool

This tool provides useful summaries of container vulberability reports. It is based on on [anchore/anchore-engine](https://github.com/anchore/anchore-engine), which provides complete vulnerability reports.

The tool provides the following summaries:

- \# of vulnerabilities in a given image digest, categorized by severity.
- new vulnerabilities in a given image digest relative to a previous image digest for a given tag, categorized by serverity
- resolved vulnerabilities in a given image digest relative to a previous image digest for a given tag, categorized by serverity

## Context

The tool was written around three basic assumptions:

- Developers update to the latest digests for a given tag quickly, either as a matter of policy or circumstance (active CI).
- All container images have vulnerabilities, both disclosed and not. In most cases, critical vulnerabilities are not  introduced *and* disclosed at the same time. If this were the case, then a critical vulnerability would only exist in the latest digest for a given tag. That would be easy to manage! Instead, in real life, critical vulnerabilities are introduced long before they are disclosed, existing in the distro/product for a long time.
- The decision to pull/accept a newer image digest should be based not on total or specific vulnerabilities but on the reduction or addition of vulnerabilities between two digests (the one you are using now, and the one you are considering using). Assuming you cannot take down your application or easily change base images, then the diff in vulnerabilities is what you should be studying.

## Vulnerability data

The [anchore-engine](https://github.com/anchore/anchore-engine) provides significant vulnerability information that is useful for both old and new image digests. For a given query, it provides current vulnerability information for a given digest. It does not provide a view of that image digest at any other point in time.

The following additional data is important in order to produce the summaries described above:

- Security vulnerabilities present in a digest for a given tag when a later digest is made made available for a given tag.

This information is particularly useful for developers that quickly move to the latest digest for a given tag as a matter of course. One expects that keeping up with the latest digest has a very different vulnerability exposure than using older digests.

## Installing the Tool

You need to [install](https://anchore.freshdesk.com/support/solutions/articles/36000020728-overview) the [anchore/anchore-engine](https://github.com/anchore/anchore-engine). I use the [Install with Docker Compose](https://anchore.freshdesk.com/support/solutions/articles/36000020729-install-with-docker-compose) workflow.

## Using Tool

- Register images
- Request summaries

