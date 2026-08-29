module.exports = function (api) {
  api.cache(true);
  return {
    presets: [['babel-preset-expo', { reanimated: false, worklets: false }]],
    // Reanimated 4 moved its Babel transform into react-native-worklets.
    // Keep this plugin last so every worklet receives __initData metadata.
    plugins: ['react-native-worklets/plugin'],
  };
};
