# Disassembling Terabytes of Random Data with Zig and Capstone to Prove a Point

This repository contains the code that accompanies my [blog
post](https://jstrieb.github.io/posts/random-instructions) and [research
paper](https://github.com/jstrieb/random-instructions/raw/master/paper/paper.pdf)
(containing nearly identical content) exploring whether it is more likely to
encounter valid, assembled Thumb instructions or valid DEFLATE-compressed data
(particularly compressed Thumb instructions) in random streams of bytes.

I originally embarked on this research to prove my friend (who has a PhD)
wrong. You'll have to read the post or paper to find out the results.

## Code

This repository includes all of the code and data required to replicate my
results from the paper. 

- [`Makefile`](./Makefile) should be your starting point
  - Just running `make` (assuming you have all of the dependencies) should
    trigger all of the required build steps to replicate the data
  - The dependencies are documented in the `Makefile` itself, and Make should
    alert you if you are missing anything
- [`build.zig`](./build.zig) and [`src`](./src) contain the high-performance
  (but not particularly well-optimized) Zig code to run the experiments and
  collect data
  - [`src/main.zig`](./src/main.zig) is the CLI application to run tests
    involving disassembly and decompression together
  - [`src/inflate.zig`](./src/inflate.zig) is the CLI application to run tests
    involving only decompression
- [`graphs`](./graphs) contains the
  [Vega-Lite](https://vega.github.io/vega-lite/) specifications for the graphs
  used in the post and paper, as well as some committed copies of the CSV data
  used to build the specific graphs I used
  - The NodeJS dependencies of the Vega-Lite CLI applications are in
    [`package.json`](./package.json)
- [`paper`](./paper) includes the Markdown file
  ([`paper.md`](./paper/paper.md)) with the paper's contents, and the PDF built
  from that Markdown file ([`paper.pdf`](./paper/paper.pdf))

## Project Status & Contributing

As far as I'm concerned, this project is done. I have already gone way
overboard in belaboring the topic.

That being said, if you want to continue the research, [I would love to hear
about your results over email or via my website's contact
form](https://jstrieb.github.io/about#contact).


