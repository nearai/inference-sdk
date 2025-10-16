export type IntelTdxVerification = {
  success: boolean;
  quote: {
    verified: boolean;

    [k: string]: unknown;
  };

  [k: string]: unknown;
};
