// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from "vscode";
import axios from "axios";

interface CustomTerminalLink extends vscode.TerminalLink {
  data: string;
}

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {
  // Get server from configuration
  let server = vscode.workspace
    .getConfiguration("retoolsync")
    .get<string>("server", "http://localhost:6969");

  // Remove trailing /
  if (server.endsWith("/")) {
    server = server.substring(0, server.length - 1);
  }

  // https://stackoverflow.com/a/58139566/1806760
  let debug = vscode.window.createOutputChannel("REToolSync");
  debug.appendLine(`REToolSync server: ${server}`);

  // Reference: https://www.eliostruyf.com/handle-links-in-the-terminal-from-your-vscode-extension/
  const linkDisposable = vscode.window.registerTerminalLinkProvider({
    provideTerminalLinks: (
      context: vscode.TerminalLinkContext,
      token: vscode.CancellationToken
    ) => {
      // Detect the first instance of the word "link" if it exists and linkify it
      const matches = [...context.line.matchAll(/0x[0-9a-fA-F]+/g)];

      return matches.map((match) => {
        const line = context.line;

        const startIndex = line.indexOf(match[0]);

        debug.appendLine(`Found potential address: ${match[0]}`);

        return {
          startIndex,
          length: match[0].length,
          tooltip: "REToolSync: Goto address",
          data: match[0],
        } as CustomTerminalLink;
      });
    },
    handleTerminalLink: async (link: CustomTerminalLink) => {
      const address = link.data;
      vscode.window.showInformationMessage(
        `REToolSync: Goto address: ${address}`
      );
      try {
        debug.appendLine(`Goto address: ${address}`);
        const { data, status } = await axios.post(
          `${server}/api/goto?address=${address}`,
          null,
          {
            headers: {
              // eslint-disable-next-line @typescript-eslint/naming-convention
              "User-Agent": "REToolSync VSCode",
            },
          }
        );
        debug.appendLine(`Status: ${status}, Data: ${data}`);
      } catch (error) {
        const message = `Failed to goto address ${address}: ${error}`;
        debug.appendLine(message);
        vscode.window.showErrorMessage(message);
      }
    },
  });

  // The command has been defined in the package.json file
  // Now provide the implementation of the command with registerCommand
  // The commandId parameter must match the command field in package.json
  const commandDisposable = vscode.commands.registerCommand(
    "retoolsync.helloWorld",
    () => {
      // The code you place here will be executed every time your command is executed
      // Display a message box to the user
      vscode.window.showInformationMessage("Hello World from REToolSync!");
    }
  );

  // Clean up properly
  context.subscriptions.push(linkDisposable, commandDisposable);
}

// This method is called when your extension is deactivated
export function deactivate() {}
