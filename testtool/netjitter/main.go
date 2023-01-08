package main

import (
	"bufio"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"log"
	"math"
	"os"
	"strconv"
)

var (
	input  string
	output string
)

func init() {
	flag.StringVar(&input, "i", "input.txt", "input network latency")
	flag.StringVar(&output, "o", "output.jpeg", "output jpeg path")
	flag.Parse()
}

func main() {
	file, err := os.Open(input) // #nosec
	checkError(err)
	defer func() { _ = file.Close() }()

	// read samples
	sample := make([]int, 0, 2048)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		s, err := strconv.Atoi(scanner.Text())
		checkError(err)
		sample = append(sample, s)
	}

	// find minimum and maximum sample
	min := math.MaxInt
	max := 0
	for i := 0; i < len(sample); i++ {
		if sample[i] < min {
			min = sample[i]
		}
		if sample[i] > max {
			max = sample[i]
		}
	}
	fmt.Println("minimum latency:", min)
	fmt.Println("maximum latency:", max)

	// initialize grid
	width := len(sample)
	height := max - min

	grid := make([][]bool, width)
	for x := 0; x < len(grid); x++ {
		grid[x] = make([]bool, height+1)
	}

	// draw point
	for x := 0; x < width; x++ {
		y := max - sample[x]
		grid[x][y] = true
	}

	// padding grid
	for x := 0; x < width; x++ {
		for y := height; y > 0; y-- {
			if grid[x][y] {
				break
			}
			grid[x][y] = true
		}
	}

	// generate result image
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			if grid[x][y] {
				img.Set(x, y, color.Black)
			} else {
				img.Set(x, y, color.White)
			}
		}
	}
	dst, err := os.Create(output) // #nosec
	checkError(err)
	defer func() { _ = dst.Close() }()
	err = jpeg.Encode(dst, img, nil)
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
