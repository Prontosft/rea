import {
  PROMPT_CONTRACTS,
  guidedPromptArgumentsSchema,
  guidedPromptInventory,
  guidedWorkflowsInputSchema,
  renderGuidedPrompt,
  type PromptContract,
} from "../contracts/promptContracts.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../domain/result.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";

export const GUIDED_WORKFLOWS_OPERATION = "guided_workflows";

/** Validate and perform a provider-free list or render request. */
export const accessGuidedWorkflows = (
  input: unknown,
): Result<JsonValue, AnalysisInputError> => {
  const parsed = guidedWorkflowsInputSchema.safeParse(input);
  if (!parsed.success)
    return err(
      analysisInputErrorFromIssues(
        GUIDED_WORKFLOWS_OPERATION,
        parsed.error.issues,
        input,
      ),
    );

  if (parsed.data.action === "list") {
    if (
      parsed.data.workflow_id !== undefined ||
      parsed.data.arguments !== undefined
    )
      return invalidInput("For action=list, omit workflow_id and arguments.", [
        {
          path: [
            parsed.data.workflow_id !== undefined ? "workflow_id" : "arguments",
          ],
          reason: "invalid_value",
        },
      ]);
    return ok(
      jsonValueSchema.parse({
        action: "list",
        workflows: guidedPromptInventory(),
      }),
    );
  }

  const id = parsed.data.workflow_id;
  if (id === undefined || id.trim().length === 0)
    return invalidInput("For action=render, supply workflow_id.", [
      { path: ["workflow_id"], reason: "missing_argument" },
    ]);

  const contract = PROMPT_CONTRACTS.find(({ name }) => name === id);
  if (contract === undefined)
    return invalidInput(
      `Unknown workflow_id '${id}'. Use action=list to see the available identifiers.`,
      [{ path: ["workflow_id"], reason: "invalid_value" }],
    );

  const arguments_ = parsed.data.arguments ?? {};
  const validated = guidedPromptArgumentsSchema(contract).safeParse(arguments_);
  if (!validated.success) {
    const missing = requiredArgumentNames(contract, arguments_);
    return err(
      analysisInputErrorFromIssues(
        GUIDED_WORKFLOWS_OPERATION,
        validated.error.issues,
        input,
        {
          userMessage:
            missing.length === 0
              ? "Correct the named guided workflow arguments and retry."
              : `Missing required arguments for ${id}: ${missing.join(", ")}.`,
        },
      ),
    );
  }

  return ok(
    jsonValueSchema.parse({
      action: "render",
      workflow_id: id,
      rendered_prompt: renderGuidedPrompt(
        contract,
        Object.fromEntries(
          Object.entries(validated.data).filter(
            (entry): entry is [string, string] => typeof entry[1] === "string",
          ),
        ),
      ),
    }),
  );
};

const requiredArgumentNames = (
  contract: PromptContract,
  input: Readonly<Record<string, string>>,
): string[] =>
  Object.entries(contract.arguments)
    .filter(
      ([name, argument]) =>
        argument.required &&
        (input[name] === undefined || input[name]?.trim().length === 0),
    )
    .map(([name]) => name);

const invalidInput = (
  userMessage: string,
  additionalIssues: ConstructorParameters<typeof AnalysisInputError>[2],
): Result<never, AnalysisInputError> =>
  err(
    new AnalysisInputError(
      GUIDED_WORKFLOWS_OPERATION,
      { userMessage },
      additionalIssues,
    ),
  );
