package ml

import (
	"math"
	"math/rand"
	"sync"
)

// IsolationForest is an unsupervised anomaly detection algorithm.
// It isolates anomalies by randomly partitioning the feature space.
// Anomalies require fewer partitions to isolate (shorter path length).
type IsolationForest struct {
	mu         sync.RWMutex
	trees      []*iTree
	numTrees   int
	sampleSize int
	trained    bool
}

// iTree is a single isolation tree.
type iTree struct {
	root   *iNode
	height int
}

// iNode is a node in an isolation tree.
type iNode struct {
	left         *iNode
	right        *iNode
	splitFeature int
	splitValue   float64
	size         int // number of samples in leaf
	isLeaf       bool
}

// NewIsolationForest creates a new Isolation Forest.
// numTrees: number of trees (100 is typical)
// sampleSize: subsample size per tree (256 is typical)
func NewIsolationForest(numTrees, sampleSize int) *IsolationForest {
	if numTrees <= 0 {
		numTrees = 100
	}
	if sampleSize <= 0 {
		sampleSize = 256
	}
	return &IsolationForest{
		numTrees:   numTrees,
		sampleSize: sampleSize,
	}
}

// Train builds the isolation forest from training data.
// data: rows of feature vectors (all must have the same length)
func (f *IsolationForest) Train(data [][]float64) {
	if len(data) == 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	maxHeight := int(math.Ceil(math.Log2(float64(f.sampleSize))))
	f.trees = make([]*iTree, f.numTrees)

	for i := range f.trees {
		// Subsample
		sample := subsample(data, f.sampleSize)
		tree := &iTree{height: maxHeight}
		tree.root = buildTree(sample, 0, maxHeight)
		f.trees[i] = tree
	}
	f.trained = true
}

// Score returns an anomaly score for a single sample.
// Score > 0.5 suggests anomaly; score > 0.7 is likely anomaly.
// Score close to 0.5 is normal; score close to 1.0 is highly anomalous.
func (f *IsolationForest) Score(sample []float64) float64 {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if !f.trained || len(f.trees) == 0 {
		return 0.5
	}

	var totalPathLen float64
	for _, tree := range f.trees {
		totalPathLen += pathLength(tree.root, sample, 0)
	}
	avgPathLen := totalPathLen / float64(len(f.trees))
	cn := cFactor(f.sampleSize)
	if cn == 0 {
		return 0.5
	}
	return math.Pow(2, -avgPathLen/cn)
}

// IsTrained returns whether the forest has been trained.
func (f *IsolationForest) IsTrained() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.trained
}

// buildTree recursively builds an isolation tree.
func buildTree(data [][]float64, height, maxHeight int) *iNode {
	if len(data) <= 1 || height >= maxHeight {
		return &iNode{isLeaf: true, size: len(data)}
	}

	numFeatures := len(data[0])
	if numFeatures == 0 {
		return &iNode{isLeaf: true, size: len(data)}
	}

	// Pick a random feature
	feat := rand.Intn(numFeatures)

	// Find min/max for that feature
	minVal, maxVal := data[0][feat], data[0][feat]
	for _, row := range data[1:] {
		if row[feat] < minVal {
			minVal = row[feat]
		}
		if row[feat] > maxVal {
			maxVal = row[feat]
		}
	}

	if minVal == maxVal {
		return &iNode{isLeaf: true, size: len(data)}
	}

	// Random split value in [min, max)
	splitVal := minVal + rand.Float64()*(maxVal-minVal)

	var left, right [][]float64
	for _, row := range data {
		if row[feat] < splitVal {
			left = append(left, row)
		} else {
			right = append(right, row)
		}
	}

	return &iNode{
		splitFeature: feat,
		splitValue:   splitVal,
		left:         buildTree(left, height+1, maxHeight),
		right:        buildTree(right, height+1, maxHeight),
	}
}

// pathLength computes the path length for a sample in a tree.
func pathLength(node *iNode, sample []float64, depth int) float64 {
	if node == nil || node.isLeaf {
		sz := 1
		if node != nil {
			sz = node.size
		}
		return float64(depth) + cFactor(sz)
	}
	if sample[node.splitFeature] < node.splitValue {
		return pathLength(node.left, sample, depth+1)
	}
	return pathLength(node.right, sample, depth+1)
}

// cFactor is the expected path length for a BST with n nodes.
func cFactor(n int) float64 {
	if n <= 1 {
		return 0
	}
	h := math.Log(float64(n-1)) + 0.5772156649 // Euler-Mascheroni constant
	return 2*h - (2 * float64(n-1) / float64(n))
}

// subsample returns a random subsample of data (with replacement if needed).
func subsample(data [][]float64, size int) [][]float64 {
	if len(data) <= size {
		return data
	}
	indices := rand.Perm(len(data))[:size]
	result := make([][]float64, size)
	for i, idx := range indices {
		result[i] = data[idx]
	}
	return result
}
