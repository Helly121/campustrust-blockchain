const webpack = require('webpack');
const path = require('path');

module.exports = {
    entry: './pera_entry.js',
    output: {
        filename: 'perawallet-bundle.js',
        path: path.resolve(__dirname, 'static/js'),
    },
    mode: 'production',
    plugins: [
        new webpack.optimize.LimitChunkCountPlugin({
            maxChunks: 1,
        }),
    ],
    performance: {
        hints: false,
    }
};
