#include "PrefixTreeTests.h"
#include "libPSI/PIR/BgiPirClient.h"
#include "libPSI/PIR/BgiPirServer.h"
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Crypto/PRNG.h>

using namespace osuCrypto;

//http://www.geeksforgeeks.org/linked-complete-binary-tree-its-creation/
//
// For Queue Size
#define SIZE 1<<20

// A tree 
struct node
{
	u64 data;
	struct node *right, *left;
};

// A queue node
struct Queue
{
	u64 front, rear;
	u64 size;
	struct node* *array;
};

// A utility function to create a new tree node
struct node* newNode(int data)
{
	struct node* temp = (struct node*) malloc(sizeof(struct node));
	temp->data = data;
	temp->left = temp->right = NULL;
	return temp;
}

// A utility function to create a new Queue
struct Queue* createQueue(int size)
{
	struct Queue* queue = (struct Queue*) malloc(sizeof(struct Queue));

	queue->front = queue->rear = -1;
	queue->size = size;

	queue->array = (struct node**) malloc(queue->size * sizeof(struct node*));

	u64 i;
	for (i = 0; i < size; ++i)
		queue->array[i] = NULL;

	return queue;
}

// Standard Queue Functions
u64 isEmpty(struct Queue* queue)
{
	return queue->front == -1;
}

u64 isFull(struct Queue* queue)
{
	return queue->rear == queue->size - 1;
}

u64 hasOnlyOneItem(struct Queue* queue)
{
	return queue->front == queue->rear;
}

void Enqueue(struct node *root, struct Queue* queue)
{
	if (isFull(queue))
		return;

	queue->array[++queue->rear] = root;

	if (isEmpty(queue))
		++queue->front;
}

struct node* Dequeue(struct Queue* queue)
{
	if (isEmpty(queue))
		return NULL;

	struct node* temp = queue->array[queue->front];

	if (hasOnlyOneItem(queue))
		queue->front = queue->rear = -1;
	else
		++queue->front;

	return temp;
}

struct node* getFront(struct Queue* queue)
{
	return queue->array[queue->front];
}

// A utility function to check if a tree node has both left and right children
int hasBothChild(struct node* temp)
{
	return temp && temp->left && temp->right;
}

// Function to insert a new node in complete binary tree
void insert(struct node **root, int data, struct Queue* queue)
{
	// Create a new node for given data
	struct node *temp = newNode(data);

	// If the tree is empty, initialize the root with new node.
	if (!*root)
		*root = temp;

	else
	{
		// get the front node of the queue.
		struct node* front = getFront(queue);

		// If the left child of this front node doesn’t exist, set the
		// left child as the new node
		if (!front->left)
			front->left = temp;

		// If the right child of this front node doesn’t exist, set the
		// right child as the new node
		else if (!front->right)
			front->right = temp;

		// If the front node has both the left child and right child,
		// Dequeue() it.
		if (hasBothChild(front))
			Dequeue(queue);
	}

	// Enqueue() the new node for later insertions
	Enqueue(temp, queue);
}

// Standard level order traversal to test above function
void PrintByLevel(struct node* root)
{
	struct Queue* queue = createQueue(SIZE);

	Enqueue(root, queue);

	while (!isEmpty(queue))
	{
		struct node* temp = Dequeue(queue);

		std::cout<< " "<< temp->data;

		if (temp->left)
			Enqueue(temp->left, queue);

		if (temp->right)
			Enqueue(temp->right, queue);
	}
}


struct node *findPrefix(node *root, int n1, int n2)
{
	// Base case
	if (root == NULL) return NULL;

	//n1 or n2 is a root of other
	if (root->data == n1 || root->data == n2)
		return root;

	node *left_prefix = findPrefix(root->left, n1, n2);
	node *right_prefix = findPrefix(root->right, n1, n2);

	// If both of the above calls return Non-NULL, then one key
	// is present in once subtree and other is present in other,
	// So this node is the Prefix
	if (left_prefix && right_prefix)  return root;

	// Otherwise check if left subtree or right subtree is Prefix
	return (left_prefix != NULL) ? left_prefix : right_prefix;
}


void Prefix_test() {

	u64 depth = 4;
	struct node* root = NULL;
	struct Queue* queue = createQueue(SIZE);
	u64 i;

	//build a tree
	for (i = 1; i < (u64)(1 << (depth+1)); ++i)
		insert(&root, i, queue);

	//PrintByLevel(root);

	
	u64 numCuckoo = 1 << 2; // 10;
	u64 numLeaves = 1 << depth; // start from 2^d to 2^(d+1)-1
	std::cout << "Leaves starts at: " << numLeaves;

	std::vector<u64> idxCuckoo(numCuckoo);
	std::cout << "\nCuckoo: ";
	for (u64 i = 0; i < numCuckoo; i++)
	{
		idxCuckoo[i] = rand() % numLeaves+ numLeaves;
		std::cout << idxCuckoo[i] << " ";
	}

	//compute prefix
	std::map<int, int> bins; //<common node,  #pair>

	for (u64 i = 0; i < numCuckoo; i++)
		for (u64 j = i+1; j < numCuckoo; j++)
		{
			struct node* temp = findPrefix(root, idxCuckoo[i], idxCuckoo[j]);

			if (bins.find(temp->data) == bins.end()) {
				bins[temp->data] = 1;
			}
			else {
				bins[temp->data] ++;
			}

			std::cout << "\nPrefix("<< idxCuckoo[i]<<", " << idxCuckoo[j]<< ") = " 
				<< temp->data;
		}

	std::cout <<  "\n";
	for (auto elem : bins)
	{
		std::cout << elem.first << " " << elem.second << "\n";
	}


}