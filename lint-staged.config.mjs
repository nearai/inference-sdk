export default {
  'lint-staged.config.mjs': (filenames) => {
    const files = filenames.map((filename) => `../${filename}`).join(' ');
    return [
      `cd js && prettier --write ${files}`,
      `cd js && eslint --fix ${files}`,
    ];
  },
  'js/**/*.{ts,mjs}': (filenames) => {
    const files = filenames.map((filename) => filename.replace(/^js\//, '')).join(' ');
    return [
      `cd js && prettier --write ${files}`,
      `cd js && eslint --fix ${files}`,
    ];
  },
  'py/**/*.py': (filenames) => {
    const files = filenames.map((filename) => filename.replace(/^py\//, '')).join(' ');
    return [
      `cd py && ruff format ${files}`,
      `cd py && ruff check --fix ${files}`,
    ];
  },
};
