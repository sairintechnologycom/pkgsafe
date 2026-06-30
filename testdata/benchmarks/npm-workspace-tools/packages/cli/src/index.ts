import chalk from "chalk";
import fg from "fast-glob";
import { Command } from "commander";

const program = new Command();
program.action(async () => {
  const files = await fg(["src/**/*.ts"]);
  console.log(chalk.green(`indexed ${files.length} files`));
});
