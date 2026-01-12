Your task is to implement a fully fledged DDOS protection company called PistonProtection.
- ddos protection management panel written with:
  - shadcn/ui (baseui theme): pnpm dlx shadcn@latest create --preset "https://ui.shadcn.com/init?base=base&style=nova&baseColor=zinc&theme=zinc&iconLibrary=lucide&font=inter&menuAccent=subtle&menuColor=default&radius=default&template=start" --template start
  - react
  - tanstack start
  - tanstack query
  - tanstack form
  - postgres backend
  - redis cache
  - users should be able to sign up, subscribe and configure ddos protection for them
  - the dashboard will provide them with live metrics that are fetched and also setup instructions to configure their domains and endpoints
  - use stripe + better auth for authentication. use better-auth-ui for auth. here is an example usage: (must use gh cli to fetch) https://github.com/mineads-gg/mineads-website 
- Advanced eBPF and XDP filter stacks on the worker nodes
- Build it all based on kubernetes with ciliumm, operators, etc.
- allow self hosting it
- open source it all on the PistonProtection github organization
- supported software on L7 with L7 filtering:
  - TCP
  - UDP
  - QUIC (raw QUIC)
  - Minecraft Java Edition
  - Minecraft Bedrock edition
  - HTTP1/HTTP2/HTTP3
  - analyze all these protocols and write proper filters for cilium and eBPF/XDP for them that are configurable via the dashboard.
- grafana in the stack
- prometheus in the stack
- loki in the stack

All modules except the frontend must be written in rust.
Use protobufs AND gRPC for inter-components communication. json/superjson is okay for browser <-> frontend communication.

Frequently use git and the gh cli for git operations.
Use subagents and cli commands as much is needed to complete the whole task.

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
