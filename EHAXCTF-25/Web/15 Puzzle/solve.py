import requests
import json
import re
from queue import PriorityQueue
import time
import urllib.parse

class PuzzleState:
    def __init__(self, board, moves=None, parent=None):
        self.board = board
        self.moves = moves if moves else []
        self.parent = parent
        self._hash = None
        
    def __eq__(self, other):
        return self.board == other.board
    
    def __hash__(self):
        if self._hash is None:
            self._hash = str(self.board).__hash__()
        return self._hash
    
    def __lt__(self, other):
        return False
    
    def get_empty_pos(self):
        for i in range(4):
            for j in range(4):
                if self.board[i][j] == 0:
                    return i, j
        return None

    def get_linear_conflicts(self):
        conflicts = 0
        # Check rows
        for i in range(4):
            for j in range(4):
                if self.board[i][j] == 0:
                    continue
                target_row = (self.board[i][j] - 1) // 4
                if target_row == i:
                    for k in range(j + 1, 4):
                        if self.board[i][k] != 0:
                            target_row_k = (self.board[i][k] - 1) // 4
                            if target_row_k == i and self.board[i][j] > self.board[i][k]:
                                conflicts += 2
        # Check columns similarly
        for j in range(4):
            for i in range(4):
                if self.board[i][j] == 0:
                    continue
                target_col = (self.board[i][j] - 1) % 4
                if target_col == j:
                    for k in range(i + 1, 4):
                        if self.board[k][j] != 0:
                            target_col_k = (self.board[k][j] - 1) % 4
                            if target_col_k == j and self.board[i][j] > self.board[k][j]:
                                conflicts += 2
        return conflicts

    def get_manhattan_distance(self):
        distance = 0
        for i in range(4):
            for j in range(4):
                if self.board[i][j] != 0:
                    value = self.board[i][j]
                    target_row = (value - 1) // 4
                    target_col = (value - 1) % 4
                    distance += abs(target_row - i) + abs(target_col - j)
        return distance + self.get_linear_conflicts()

    def is_solvable(self):
        # Convert board to 1D array excluding empty tile
        flat = []
        empty_row = 0
        for i, row in enumerate(self.board):
            for val in row:
                if val == 0:
                    empty_row = 3 - i  # Distance from bottom
                else:
                    flat.append(val)
        
        # Count inversions
        inversions = 0
        for i in range(len(flat)):
            for j in range(i + 1, len(flat)):
                if flat[i] > flat[j]:
                    inversions += 1
        
        print(f"Debug - Inversions: {inversions}, Empty row from bottom: {empty_row}")
        return (inversions + empty_row) % 2 == 0

    def get_next_states(self):
        states = []
        empty_row, empty_col = self.get_empty_pos()
        # When empty space moves down, the tile moves up, etc.
        # So we store the movement of the empty space directly
        directions = [(-1, 0), (1, 0), (0, -1), (0, 1)]  # up, down, left, right
        
        for dr, dc in directions:
            new_row, new_col = empty_row + dr, empty_col + dc
            if 0 <= new_row < 4 and 0 <= new_col < 4:
                new_board = [row[:] for row in self.board]
                new_board[empty_row][empty_col] = new_board[new_row][new_col]
                new_board[new_row][new_col] = 0
                # Store the movement of the empty space
                new_moves = self.moves + [[dr, dc]]
                states.append(PuzzleState(new_board, new_moves, self))
        
        return states

def extract_puzzle_state(html):
    match = re.search(r'let puzzle = (\[\[.*?\]\]);', html)
    if match:
        puzzle_str = match.group(1)
        return eval(puzzle_str)
    return None

def solve_puzzle(puzzle_state):
    initial_state = PuzzleState(puzzle_state)
    if not initial_state.is_solvable():
        print("This puzzle configuration is not solvable!")
        return None

    target = [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 0]]
    target_state = PuzzleState(target)
    
    queue = PriorityQueue()
    visited = set()
    
    h_score = initial_state.get_manhattan_distance()
    queue.put((h_score, initial_state))
    visited.add(hash(initial_state))
    
    moves_limit = 80  # Reasonable limit for 15-puzzle
    nodes_explored = 0
    
    while not queue.empty():
        _, current_state = queue.get()
        nodes_explored += 1
        
        if nodes_explored % 1000 == 0:
            print(f"Explored {nodes_explored} nodes...")
        
        if current_state == target_state:
            print(f"Solution found after exploring {nodes_explored} nodes!")
            return current_state.moves
            
        if len(current_state.moves) >= moves_limit:
            continue
            
        for next_state in current_state.get_next_states():
            if hash(next_state) not in visited:
                visited.add(hash(next_state))
                g_score = len(next_state.moves)
                h_score = next_state.get_manhattan_distance()
                f_score = g_score + h_score
                queue.put((f_score, next_state))
    
    print(f"No solution found after exploring {nodes_explored} nodes")
    return None

def automate_solving():
    base_url = "http://chall.ehax.tech:8001"
    start_puzzle = "/p/133010fb86d74b66a672da07ff5b1d11"
    current_puzzle_url = urllib.parse.urljoin(base_url, start_puzzle)
    solved_count = 0

    while True:
        try:
            print(f"\nFetching puzzle from: {current_puzzle_url}")
            response = requests.get(current_puzzle_url)
            # Print response for debugging
            print(f"Response status: {response.status_code}")
            print("Response text:")
            print(response.text)

            puzzle_state = extract_puzzle_state(response.text)
            if not puzzle_state:
                print("Failed to extract puzzle state")
                break

            print("Current puzzle state:")
            for row in puzzle_state:
                print(row)

            print("\nAnalyzing puzzle solvability...")
            movements = solve_puzzle(puzzle_state)
            
            if not movements:
                print("Could not find a solution for this puzzle")
                break

            print(f"Found solution with {len(movements)} moves")
            print("Moves sequence:", movements)

            check_url = current_puzzle_url + "/check"
            print(f"Sending solution to: {check_url}")
            
            response = requests.post(
                check_url,
                headers={"Content-Type": "application/json"},
                json={"movements": movements}
            )

            print(f"Check response status: {response.status_code}")
            print("Check response text:")
            print(response.text)

            if response.status_code != 200:
                print(f"Failed to submit solution: {response.status_code}")
                break

            result = response.json()
            
            if result.get("solved"):
                solved_count += 1
                print(f"\nPuzzle solved! ({solved_count} puzzles solved)")
                next_puzzle = result.get("next_puzzle")
                if next_puzzle:
                    print(f"Moving to next puzzle...")
                    current_puzzle_url = urllib.parse.urljoin(base_url, next_puzzle)
                    time.sleep(1)  # Small delay between puzzles
                else:
                    print("No next puzzle provided")
                    break
            else:
                print("Solution was not correct")
                break

        except Exception as e:
            print(f"Error occurred: {e}")
            if hasattr(e, 'response'):
                print("Response status:", e.response.status_code)
                print("Response text:")
                print(e.response.text)
            break

if __name__ == "__main__":
    automate_solving()
