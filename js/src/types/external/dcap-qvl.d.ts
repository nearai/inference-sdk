/* eslint-disable @typescript-eslint/no-explicit-any */
declare module '@phala/dcap-qvl' {
  export function getCollateral(
    pccsUrl: string,
    quoteBytes: Uint8Array,
  ): Promise<any>;

  export function verify(
    quoteBytes: Uint8Array,
    collateral: any,
    nowSec: number,
  ): any;
}
