export type IntelTdxVerificationData = {
  quote: {
    verified: boolean;
    body: {
      mrconfig: string;
      reportdata: string;
    };
  };
};
