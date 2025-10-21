export type IntelTdxVerification = {
  success: boolean;
  quote: {
    verified: boolean;
    body: {
      mrconfig: string;
      reportdata: string;
    };
  };
};
