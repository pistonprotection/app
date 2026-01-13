Your task is to implement a fully fledged DDOS protection company called PistonProtection.

First fetch and clone and pull the latest version of all repositories from the github org. (If they dont exist in the pwd)

You can make breaking changes and drop legacy systems. This app isn't launched yet, so you can delete code, change db schema, delete repos freely.

You might be tempted to only make changes on the frontend, but the filters also need work. Make sure all parts of the app are flourishing!

Make frequent git commit and git pushes, so code stays up-to-date and properly segregated. e.g. one commit per major feature

Make sure you use latest version of all dependencies and resolve any conflicts/issues so that the latest version can be used.

Also don't use any old or unsupported or deprecated dependencies such as otel instead of tempo or promtail instead of grafanas promtail replacement because promtail is being dropped support for.

Make sure there are no modules that are obsolete/deprecated and there is no "unused" functionality.
Make sure all things work that are defined in code and have actual use for the app. e.g. dont code both ipv4 and ipv6 support but only use ipv4 support.
Also don't leave a documentation module when documentations should be in the frontend module.
E.g. remove useless modules and make sure the codebase is clean.

Use rudt nightly-2026-01-10 and latest syntax and features and editions.

- ddos protection management panel written with:
  - shadcn/ui (baseui theme, not radix theme)
  - shadcn/ui used idiomatically, use components where possible. always consider all available shadcn components for a design
  - trpc
  - typescript
  - tailwindcss
  - react
  - tanstack start
  - tanstack query
  - tanstack form
  - tanstack table
  - make sure you have nice graphs/charts
  - postgres backend
  - redis cache
  - resend for emails
  - frontend and website backend in the same repository (so it's typesafe via trpc)
  - fumadocs (built into the tanstack start frontend, not in a separate app)
  - drizzle orm
  - users should be able to sign up, subscribe and configure ddos protection for them
  - the dashboard will provide them with live metrics that are fetched and also setup instructions to configure their domains and endpoints
  - use stripe for billing (through better auth, look at mineads-website for that)
  - better auth for authentication and all its features. use better-auth with @daveyplate/better-auth-ui for auth. here is an example usage: (must use gh cli to fetch) https://github.com/mineads-gg/mineads-website
  - make sure you use @daveyplate/better-auth-ui just like in (must use gh cli to fetch) https://github.com/mineads-gg/mineads-website
  - make sure you use a similar trpc/better-auth/stripe/docs approach as mineads-website
  - read dependency documentation if something is weird
  - frontend backend must be written in typescript and use trpc just like mineads-website. and interact with the better auth ts sdk 
  - admin section for observing users and blacklists per org, etc. org info for PistonProtection admins
  - the frontend backen should be writte in typescript + tanstack starts primitives
  - make sure you use pnpm, not any other package manager
  - biome for code style on strict "all" config
  - ensure there is a full-fledged frontpage for this dashboard which talks about the product, has navbar/etc. with login button
  - make it all one big webapp for both getting customers and for customers to log into the dashboard at.
  - make sure it looks pretty and SEO is good
  - supports BOTH usage based billing and flat package billing with a fixed usage amount. for usage based billing add warning + usage cap support that is configurable.
  - also support mixes of flat billing and usage based billing
- Advanced eBPF and XDP filter stacks on the worker nodes
- Build it all based on kubernetes with ciliumm, operators, etc.
- allow self hosting it
- open source it all on the PistonProtection github organization
- supported software on L7 with L7 filtering:
  - TCP
  - UDP
  - QUIC (raw QUIC without HTTP3)
  - Minecraft Java Edition
  - Minecraft Bedrock edition
  - HTTP1/HTTP2/HTTP3
  - analyze all these protocols and write proper filters for cilium and eBPF/XDP for them that are configurable via the dashboard.
  - common attack patterns like udp floods, tcp syn flood, etc. must be filtered
  - blacklists must be maintained
  - each ip needs some type of score
  - users can lookup ip scores in their own dashboard panel to see how players would join or failed connection attempts
  - more specialized attack patterns for each service type must be blocked too
  - support haproxy protocol for backend communication being enabled via dashboard
  - support backend endpoint loadbalancing
  - support geodns loadbalancing
  - it definitely should add more RakNet level checks. There are plenty of RakNet vulns (Like amplification attacks)
  - research all protocols on the web and find common exploits/behaviour to patch
  - Where is the state of the Java protocol even set, how do the transitions work? Also where is the check for disabling the filter once encryption is enabled?
  - Also that packet id check is extremely dumb. It does id > [max packet id] but a varint can be negative
  - It should have made the packet filter as a standalone thing for testing. Testing the entire thing at once and fixing every problem will probably take months
  - Does the packet filter even check for fragmentation? What happens if a packets is split between multiple calls?
  - You can take inspiration from https://github.com/Outfluencer/Minecraft-XDP-eBPF
  - add support for newer mc packet changes such as the TRANSFER state intent
  - make sure there is no super dumb play state packet id check
- grafana in the stack
- prometheus in the stack
- loki in the stack
- clickhouse for event storage
- show fallback on minecraft if endpoint server backend is offline
- allow custom filters/configurations in the dashboard
- add github ci to all repositories
- make sure using gh cli that all gh actions workflow succeed on github

All modules except the frontend must be written in rust.
Use protobufs AND gRPC for inter-components communication. json/superjson is okay for browser <-> frontend communication.

Frequently use git and the gh cli for git operations.
Use subagents and cli commands as much is needed to complete the whole task.

Use gh cli to create repos/configure stuff for the org, etc.

Bundle this whole stack in a public helm chart.
The setup will have to have k0s with cilium with the following config:
cilium install --version "${CILIUM_VERSION}" \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost="${CONTROLLER_IP}" \
  --set k8sServicePort=6443 \
  --set hubble.enabled=true \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true \
  --set l2announcements.enabled=true \
  --set cni.chainingMode=portmap \
  --set cni.externalRouting=true \
  --set encryption.enabled=true \
  --set encryption.type=wireguard \
  --set encryption.nodeEncryption=true \
  --set cni.enableRouteMTUForCNIChaining=true \
  --set MTU=1366

This is effectively a TCPShield/Papyrus/NeoProtect clone. So ensure you also make sure we have what the competition has feature-wise.

Make sure all is pushed and all is published and set up for usage.
Run local tests, builds, run a test cluster using minikube, etc.

Use mcp servers where it makes sense for research. Also make web searches where needed.

Run tests that all components work well together and will hold up in production.

There is always something to add. If you think you added everything that's possib,e you're wrong. There can always be added another feature, test, configuration, protocol, check, etc. 
And design and frontend can always be improved. Or extra documentation written.

For documentation and better auth ui research this project: 
https://github.com/mineads-gg/mineads-website

If something is implemented incorrectly, rewrite it to be implemented the correct way.

Make sure the rust code is idiomatic and uses best and clean and safe apis. Like no reckless unwrap or unsafe when not needed.
