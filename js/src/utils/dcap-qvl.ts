export async function getDcapQvlUtils() {
  let module;

  if (typeof window === 'undefined') {
    module = await import('@phala/dcap-qvl-node');
  } else {
    module = await import('@phala/dcap-qvl-web');
  }

  return {
    jsVerify: module.js_verify,
    jsGetCollateral: module.js_get_collateral,
  };
}
