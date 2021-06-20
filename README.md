# Better NPM Audit

Made to allow skipping certain vulnerabilities, and any extra handling that are not supported by the default `npm audit` in the future.

[![NPM](https://nodei.co/npm/better-npm-audit.png)](https://npmjs.org/package/better-npm-audit)

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com) ![GitHub issues](https://img.shields.io/github/issues/jeemok/better-npm-audit?style=flat-square) ![npm bundle size](https://img.shields.io/bundlephobia/minzip/better-npm-audit?style=flat-square)

## Supports both NPM version 6 and 7

NPM has upgraded to version 7 in late 2020 and has breaking changes on the `npm audit`. The output of npm audit has significantly changed both in the human-readable and `--json` output styles. We have added handling so it works properly in both npm versions.

| Docs                       | Link                                                                                       |
| -------------------------- | ------------------------------------------------------------------------------------------ |
| NPM v6 & v7 changes        | https://github.blog/2020-10-13-presenting-v7-0-0-of-the-npm-cli/                           |
| NPM v7 blog post           | https://blog.npmjs.org/post/626173315965468672/npm-v7-series-beta-release-and-semver-major |
| Official NPM v6 audit docs | https://docs.npmjs.com/cli/v6/commands/npm-audit                                           |
| Official NPM v7 audit docs | https://docs.npmjs.com/cli/v7/commands/npm-audit                                           |
| Dealing with new npm audit | https://uko.codes/dealing-with-npm-v7-audit-changes                                        |

<br />

## Installation

    $ npm install better-npm-audit

or

    $ npm install -g better-npm-audit

<br />

## Usage

### Run global

```bash
better-npm-audit audit
```

### Run with exceptions

<img src="./.README/all_good.png" alt="Demo of table displaying the security report" width="1000"/>

Unhandled or new exceptions will be highlighted:

<img src="./.README/highlighted_exceptions.png" alt="Demo of table displaying the security report" width="820"/>

### Add into package scripts

```JSON
{
  "scripts": {
    "prepush": "npm run test && npm run audit",
    "audit": "node node_modules/better-npm-audit audit"
  }
}
```

Now you can run locally or in your CI pipeline:

```bash
npm run audit
```

<br />

## Options

| Flag              | Short | Description                                                                                                                   |
| ----------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------- |
| `--level`         | `-l`  | Same as the original `--audit-level` flag                                                                                     |
| `--production`    | `-p`  | Skip checking `devDependencies`                                                                                               |
| `--ignore`        | `-i`  | For skipping certain advisories                                                                                               |

<br />

## Environment Variables

| Variable                             | Description                                                                                                       |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| `NPM_CONFIG_AUDIT_LEVEL` | Used in setting the audit level. <br /> *Note: this will be disregard if the audit level flag is passed onto the command.* |

<br />

## Using `.nsprc` file to manage exceptions

You may add a file `.nsprc` to your project root directory to manage the exceptions. For example:

```json
{
  "1337": {
    "active": true,
    "notes": "Ignored since we don't use xxx method",
    "expiry": 1615462134681
  },
  "4501": {
    "active": false,
    "notes": "Ignored since we don't use xxx method"
  },
  "980": "Ignored since we don't use xxx method",
  "Note": "Any non number key will not be excepted"
}
```

When using `.nsprc` file, you will see this report display when it starts running:

<img src="./.README/exceptions_table.png" alt="Demo of table displaying a list of exceptions" width="820"/>


<br />

## Changelog

You can find the changelog [here](https://github.com/jeemok/better-npm-audit/blob/master/CHANGELOG.md).

<br />

## Special mentions

- [@IanWright](https://github.com/IPWright83) for his solutions in improving the vulnerability validation for us to have the minimum-audit-level and production-mode flags.

- [@EdwinTaylor](https://github.com/alertme-edwin) for all the bug reports and improvement suggestions.

- [@MrHus](https://github.com/MrHus) for the logging of unused exceptions from the .nsprc file and -ignore flags. Courtesy of 42 BV.

<br />

---

If you like this project,

<a href="https://www.buymeacoffee.com/jeemok" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>
