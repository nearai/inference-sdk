export async function getDcapQvlUtils() {
  if (typeof window === 'undefined') {
    const { js_verify, js_get_collateral } = await import(
      '@phala/dcap-qvl-node'
    );
    return {
      jsVerify: js_verify,
      jsGetCollateral: js_get_collateral,
    };
  } else {
    const {
      js_verify,
      js_get_collateral,
      default: init,
    } = await import('@phala/dcap-qvl-web');
    const { default: wasm } = await import(
      '@phala/dcap-qvl-web/dcap-qvl-web_bg.wasm'
    );
    await init({ module_or_path: wasm });
    return {
      jsVerify: js_verify,
      jsGetCollateral: js_get_collateral,
    };
  }
}
