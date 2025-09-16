export default {
  '*.(ts|js)': () => ['pnpm check', 'pnpm lint', 'pnpm prettier'],
};
