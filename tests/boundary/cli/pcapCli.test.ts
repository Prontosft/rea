import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { expectConfigurationRefusal, serveCli } from "./cliServeHarness.js";

it.each(["inspect-pcap-client", "inspect-pcap-capture"])(
  "%s advertises a schema through the public CLI",
  async (command) => {
    const result = await serveCli([command, "--schema", "--json"]);
    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toBeTruthy();
  },
);

it.each([
  ["inspect-pcap-client"],
  ["inspect-pcap-capture", "/nonexistent/capture.pcap"],
])("%s names the missing Wireshark tool to configure", async (...argv) => {
  const result = await serveCli([...argv, "--json"], {
    REA_TSHARK_COMMAND: "/nonexistent/tshark",
    REA_CAPINFOS_COMMAND: "/nonexistent/capinfos",
  });
  expectConfigurationRefusal(
    result,
    "The selected tshark executable /nonexistent/tshark could not be found",
  );
  expectConfigurationRefusal(result, "through absolute REA_TSHARK_COMMAND");
});

it.each(["tshark", "capinfos"])(
  "names a directory selected as %s as configuration to fix",
  async (tool) => {
    const root = await createTestTempDirectory("rea-pcap-tool-directory-");
    const directory = join(root, `${tool}-directory`);
    const file = join(root, "selected-file");
    await mkdir(directory);
    await writeFile(file, "#!/bin/sh\nexit 0\n");
    const result = await serveCli(["inspect-pcap-client", "--json"], {
      REA_TSHARK_COMMAND: tool === "tshark" ? directory : file,
      REA_CAPINFOS_COMMAND: tool === "capinfos" ? directory : file,
    });
    expectConfigurationRefusal(
      result,
      `The selected ${tool} executable ${directory} is not a regular file`,
    );
    expectConfigurationRefusal(result, "through absolute REA_TSHARK_COMMAND");
  },
);

it("names a relative tool selection as configuration to fix", async () => {
  const result = await serveCli(["inspect-pcap-client", "--json"], {
    REA_TSHARK_COMMAND: "tshark",
  });
  expectConfigurationRefusal(
    result,
    "REA_TSHARK_COMMAND must be an absolute path to the tshark binary",
  );
});
