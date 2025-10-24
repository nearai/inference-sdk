export type IntelTdxVerification = {
  quote: {
    verified: boolean;
    body: {
      mrconfig: string;
      reportdata: string;
    };
  };
};
