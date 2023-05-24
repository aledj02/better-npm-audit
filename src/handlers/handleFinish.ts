import { AuditLevel } from 'src/types';
import { printSecurityReport } from '../utils/print';
import { processAuditJson, handleUnusedExceptions } from '../utils/vulnerability';
import * as fs from 'fs';

/**
 * Process and analyze the NPM audit JSON
 * @param  {String} jsonBuffer        NPM audit stringified JSON payload
 * @param  {Number} auditLevel        The level of vulnerabilities we care about
 * @param  {Array} exceptionIds       List of vulnerability IDs to exclude
 * @param  {Array} exceptionModules   List of vulnerable modules to ignore in audit results
 */
export default function handleFinish(jsonBuffer: string, auditLevel: AuditLevel, exceptionIds: string[], exceptionModules: string[]): void {
  const { unhandledIds, report, failed, unusedExceptionIds, unusedExceptionModules } = processAuditJson(
    jsonBuffer,
    auditLevel,
    exceptionIds,
    exceptionModules,
  );

  // If unable to process the audit JSON
  if (failed) {
    console.error('Unable to process the JSON buffer string.');
    // Exit failed
    process.exit(1);
    return;
  }

  // Print the security report
  if (report.length) {
    printSecurityReport(report);

    // Generate json file
    const cleanArray = report.map((innerArray) => {
      return innerArray.map((item) => {
        return item.replace(/\x1B\[\d+m/g, '');
      });
    });

    const jsonKeyValue = cleanArray.map((item) => {
      return {
        id: item[0],
        package: item[1],
        title: item[2],
        path: item[3],
        severity: item[4],
        guide: item[5],
        expired: item[6],
      };
    });

    const jsonContent = JSON.stringify(jsonKeyValue, null, 2);

    saveJsonReport(jsonContent);
  } else {
    const emptyArray: unknown[] = [];
    const jsonContent = JSON.stringify(emptyArray, null, 2);
    saveJsonReport(jsonContent);
  }

  // Handle unused exceptions
  handleUnusedExceptions(unusedExceptionIds, unusedExceptionModules);

  // Display the found unhandled vulnerabilities
  if (unhandledIds.length) {
    console.error(`${unhandledIds.length} vulnerabilities found. Node security advisories: ${unhandledIds.join(', ')}`);
    // Exit failed
    process.exit(1);
  } else {
    // Happy happy, joy joy
    console.info('🤝  All good!');
    process.exit(0);
  }
}

/**
 * Create file NPM audit JSON
 * @param  {String} jsonContent        JSON object to save
 */
function saveJsonReport(jsonContent: string) {
  try {
    if (!fs.existsSync('.sast')) {
      fs.mkdirSync('.sast');
    }
    fs.writeFileSync('.sast/better_npm_report.json', jsonContent, 'utf8');
  } catch (err) {
    console.error('Error al exportar el reporte a json:', err);
  }
}
