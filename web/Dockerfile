# syntax=docker/dockerfile:1
#
# Build context is the ksi-harness repo ROOT (so both the tool at / and the web app at /web are
# available). Referenced from CodeBuild as:
#   docker build -f web/Dockerfile -t <repo>:<tag> .
#
# ksi-harness is pure ESM JavaScript (ajv, ajv-formats, yaml) with no build step and no native
# dependencies, so — unlike proofscan's web image — there is no compile stage and no
# python3/make/g++ toolchain. The tool runs straight from src/, which the web app's run process
# imports natively.

# ---- build: install the tool's deps, then install + build the web app ----
FROM public.ecr.aws/docker/library/node:22-bookworm-slim AS build
WORKDIR /repo
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

# The tool's own dependencies (ajv/ajv-formats/yaml) must be present at /repo/node_modules: the
# web app's out-of-process runner imports ksi-harness/src/* natively at runtime, and the emitters
# resolve their schema validator from there. `prepare` (scripts/setup-git.mjs) is a no-op outside
# a git work tree, so npm ci does not fail here.
# (Optional aws-sdk deps are installed too — they are only ever imported dynamically at runtime
# by the live collectors, never on the offline fixture path this GUI drives, but installing them
# keeps the image faithful to a normal clone and removes any risk of a surprise resolution error.)
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
# The tool itself: source, the pinned FedRAMP ruleset, the routing map and schemas all travel,
# because src/* resolves the ruleset and routes from these module-relative paths at run time.
COPY src ./src
COPY vendor ./vendor
COPY schemas ./schemas
COPY scripts ./scripts

# The web app. Install with the tool already present so the `file:..` dependency resolves, then
# build. The bundled fixtures (web/ksi-fixtures) and profile (web/ksi-examples) come in with the
# COPY web below and travel in the image.
COPY web/package.json web/package-lock.json ./web/
RUN cd web && npm ci --ignore-scripts
COPY web ./web
RUN cd web && npm run build

# ---- runner: run `next start` with the full tree in place ----
FROM public.ecr.aws/docker/library/node:22-bookworm-slim AS runner
WORKDIR /repo
ENV NODE_ENV=production
ENV PORT=3220
# Offline-only overrides: the run process reads fixtures and the profile from these bundled paths
# and never contacts a real system.
ENV KSI_FIXTURES_DIR=/repo/web/ksi-fixtures
ENV KSI_PROFILE=/repo/web/ksi-examples/northwind.profile.yaml
ENV KSI_CHANGE=/repo/web/ksi-examples/change.scn.yaml

# Bring the whole built tree (tool src + vendor + node_modules, web .next + node_modules, scripts,
# bundled fixtures). The web/node_modules/ksi-harness symlink points at /repo, which exists at the
# same path here, so it resolves — and the tool's vendor/ and routes.yaml resolve module-relative.
# Owned by the built-in non-root `node` user so the runtime can read (and Next
# can write its .next/cache) without running as root.
COPY --chown=node:node --from=build /repo /repo

# Drop root: the runtime only reads bundled fixtures and serves HTTP.
USER node

WORKDIR /repo/web
EXPOSE 3220
CMD ["npx", "next", "start", "-p", "3220", "-H", "0.0.0.0"]
