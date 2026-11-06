package java

import (
	"strings"

	ts "github.com/tree-sitter/go-tree-sitter"
)

// concurrencyTypes are java.util.concurrent's tools beyond a plain thread.
var concurrencyTypes = map[string]bool{
	"ExecutorService": true, "CompletableFuture": true, "AtomicInteger": true, "AtomicLong": true, "AtomicBoolean": true, "AtomicReference": true,
	"ConcurrentHashMap": true, "ReentrantLock": true, "ReadWriteLock": true, "CountDownLatch": true, "Semaphore": true, "CyclicBarrier": true,
}

// reflectionCalls inspect classes at run time.
var reflectionCalls = map[string]bool{"getDeclaredMethod": true, "getDeclaredMethods": true, "getDeclaredField": true, "getDeclaredFields": true, "getDeclaredConstructor": true, "forName": true, "setAccessible": true}

// visitConstructs records generic types and methods, concurrency,
// reflection, and annotation types.
func (c *checker) visitConstructs(n *ts.Node) {
	switch n.Kind() {
	case "type_parameters":
		c.idiom("java.construct.generic-types", n)
	case "synchronized_statement":
		c.idiom("java.construct.concurrency", n)
	case "modifiers":
		if t := c.tree.Text(n); strings.Contains(t, "synchronized") || strings.Contains(t, "volatile") {
			c.idiom("java.construct.concurrency", n)
		}
	case "type_identifier":
		if concurrencyTypes[c.tree.Text(n)] {
			c.idiom("java.construct.concurrency", n)
		}
	case "method_invocation":
		if name := n.ChildByFieldName("name"); name != nil && reflectionCalls[c.tree.Text(name)] {
			c.idiom("java.construct.reflection", n)
		}
	case "annotation_type_declaration":
		c.idiom("java.construct.annotation-types", n)
	}
}
