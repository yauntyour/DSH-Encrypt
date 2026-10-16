//#region src/compat.d.ts
interface DshRuntime {
  /** Absolute path of the dsh package manifest the runtime was launched from. */
  path: string;
  /** The running dsh release version. */
  version: string;
}
/**
 * Find the running dsh runtime version from the process entry point.
 * @param argv - the process argv (injectable for tests).
 * @returns the runtime, or null when this process was not launched through
 *   the dsh CLI (tests, embeds).
 */
declare function detectDshRuntime(argv?: string[]): DshRuntime | null;
//#endregion
export { DshRuntime, detectDshRuntime };
//# sourceMappingURL=compat.d.ts.map