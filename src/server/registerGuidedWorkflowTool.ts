import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { accessGuidedWorkflows } from "../application/GuidedWorkflowAccess.js";
import { toolContract } from "../contracts/toolContracts.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Register provider-free access to the existing guided prompt contracts. */
export const registerGuidedWorkflowTool = (server: EvidenceMcpServer): void => {
  const contract = toolContract("guided_workflows");
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    async (input) =>
      server.delivery.toCallToolResult(accessGuidedWorkflows(input), contract),
  );
};
