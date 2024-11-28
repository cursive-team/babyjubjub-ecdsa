/* tslint:disable */
/* eslint-disable */
/**
* Verify a proof 
* @param {string} params_string
* @param {string} proof_string
* @param {string} root
* @param {number} num_steps
* @returns {Promise<Array<any>>}
*/
export function verify_proof(params_string: string, proof_string: string, root: string, num_steps: number): Promise<Array<any>>;
/**
*
* * Generates the first fold in a proof
* *
* * @param r1cs_url - the url of the r1cs file to load
* * @param wasm_url - the url of the wasm file to load
* * @param params_string - the stringified public parameters file
* * @param root - the root of the tree to prove membership in
* * @param membership_string - the stringified membership inputs
* *
* @param {string} r1cs_url
* @param {string} wasm_url
* @param {string} params_string
* @param {string} root
* @param {string} membership_string
* @returns {Promise<string>}
*/
export function generate_proof(r1cs_url: string, wasm_url: string, params_string: string, root: string, membership_string: string): Promise<string>;
/**
*
* * Compute the next step of a proof
* *
* * @param params_string - the stringified public parameters file
* * @param proof_string - the stringified proof file
* * @param membership_string - the stringified membership inputs
* * @param zi_primary - the step_out of previous proof and step_in for this proof
* * @return - the stringified proof file
* 
* @param {string} r1cs_url
* @param {string} wasm_url
* @param {string} params_string
* @param {string} proof_string
* @param {string} membership_string
* @param {Array<any>} zi_primary
* @returns {Promise<string>}
*/
export function continue_proof(r1cs_url: string, wasm_url: string, params_string: string, proof_string: string, membership_string: string, zi_primary: Array<any>): Promise<string>;
/**
*
* * Obfuscate a proof by adding in random data to the witness
* @param {string} r1cs_url
* @param {string} wasm_url
* @param {string} params_string
* @param {string} proof_string
* @param {Array<any>} zi_primary
* @returns {Promise<string>}
*/
export function obfuscate_proof(r1cs_url: string, wasm_url: string, params_string: string, proof_string: string, zi_primary: Array<any>): Promise<string>;
/**
*
* * Gzip compress a proof
* *
* * @param proof_string - the stringified json proof to compress
* * @return - the compressed proof as a Uint8Array
* 
* @param {string} proof
* @returns {Uint8Array}
*/
export function compress_proof(proof: string): Uint8Array;
/**
*
* * Gzip decompress a proof
* *
* * @param compressed - the compressed proof as a Uint8Array
* * @return - the decompressed proof as a string
* 
* @param {Uint8Array} compressed
* @returns {string}
*/
export function decompress_proof(compressed: Uint8Array): string;
/**
*/
export function init_panic_hook(): void;
/**
*
* * Get a random Fr element as a string for circuit input
* * 
* * @return - a random Fr element as a string
* 
* @returns {string}
*/
export function random_fr(): string;
/**
* @param {string} path
* @returns {Promise<Uint8Array>}
*/
export function read_file(path: string): Promise<Uint8Array>;
/**
* @param {string} input_json_string
* @param {string} wasm_file
* @returns {Promise<Uint8Array>}
*/
export function generate_witness_browser(input_json_string: string, wasm_file: string): Promise<Uint8Array>;
/**
* @param {number} num_threads
* @returns {Promise<any>}
*/
export function initThreadPool(num_threads: number): Promise<any>;
/**
* @param {number} receiver
*/
export function wbg_rayon_start_worker(receiver: number): void;
/**
*/
export class wbg_rayon_PoolBuilder {
  free(): void;
/**
* @returns {number}
*/
  numThreads(): number;
/**
* @returns {number}
*/
  receiver(): number;
/**
*/
  build(): void;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly verify_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => number;
  readonly generate_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => number;
  readonly continue_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => number;
  readonly obfuscate_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => number;
  readonly compress_proof: (a: number, b: number) => number;
  readonly decompress_proof: (a: number, b: number) => void;
  readonly random_fr: (a: number) => void;
  readonly init_panic_hook: () => void;
  readonly __wbg_wbg_rayon_poolbuilder_free: (a: number) => void;
  readonly wbg_rayon_poolbuilder_numThreads: (a: number) => number;
  readonly wbg_rayon_poolbuilder_receiver: (a: number) => number;
  readonly wbg_rayon_poolbuilder_build: (a: number) => void;
  readonly initThreadPool: (a: number) => number;
  readonly wbg_rayon_start_worker: (a: number) => void;
  readonly read_file: (a: number, b: number) => number;
  readonly generate_witness_browser: (a: number, b: number, c: number, d: number) => number;
  readonly memory: WebAssembly.Memory;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_export_3: WebAssembly.Table;
  readonly _dyn_core__ops__function__FnMut__A____Output___R_as_wasm_bindgen__closure__WasmClosure___describe__invoke__h7792a5b227a1963e: (a: number, b: number, c: number) => void;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly wasm_bindgen__convert__closures__invoke2_mut__h743b3837663524d8: (a: number, b: number, c: number, d: number) => void;
  readonly __wbindgen_thread_destroy: (a?: number, b?: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
* @param {WebAssembly.Memory} maybe_memory
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput, maybe_memory?: WebAssembly.Memory): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
* @param {WebAssembly.Memory} maybe_memory
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: InitInput | Promise<InitInput>, maybe_memory?: WebAssembly.Memory): Promise<InitOutput>;
