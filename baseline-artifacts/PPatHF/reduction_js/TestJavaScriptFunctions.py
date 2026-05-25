import unittest
# from reduction_js.fcu import FCU
from fcu import FunctionCompareUtilities as FCU

class TestJavaScriptFunctions(unittest.TestCase):
    
    def setUp(self):
        self.fcu = FCU()
        
    def test_function_declaration(self):
        """ Test traditional function declaration """
        
        code = """
        function calculateSum(numbers) {
            return numbers.reduce((a, b) => a + b, 0);
        }"""
        tree = self.fcu.parse(code.encode('utf-8'))
        functions = self.fcu.get_functions(code, tree.root_node)
        
        self.assertIn("calculateSum", functions)
        self.assertEqual(functions["calculateSum"].type, "function_declaration")
        
    def test_arrow_function(self):
        """ Test arrow function expression """
        
        code = """
        const multiply = (x, y) => {
            return x * y;
        };
        
        const square = n => n * n; // concise body
        """
        
        tree = self.fcu.parse(code.encode('utf-8'))
        functions = self.fcu.get_functions(code, tree.root_node)
        print(f"Functions found: {functions}")
        self.assertIn("multiply", functions)
        # self.assertEqual(functions["multiply"].type, "variable_declaration")
        self.assertIn("square", functions)
        # self.assertEqual(functions["square"].type, "variable_declaration")
        
    def test_method_definition(self):
        """ Test method definition in class """
        
        code = """
        class Calculator {
            add(a, b) {
                return a + b;
            }
            
            async fetchData(url) {
                const response = await fetch(url);
                return response.json();
            }
        }"""
        tree = self.fcu.parse(code.encode('utf-8'))
        functions = self.fcu.get_functions(code, tree.root_node)
        
        self.assertIn("add", functions)
        # self.assertEqual(functions["add"].type, "method_definition")
        self.assertIn("fetchData", functions)
        # self.assertEqual(functions["fetchData"].type, "method_definition")
        
    def test_generator_function(self):
        """ Test generator function """
        
        code = """
        function* idGenerator() {
            let id = 0;
            while (true) {
                yield id++;
            }
        }"""
        tree = self.fcu.parse(code.encode('utf-8'))
        functions = self.fcu.get_functions(code, tree.root_node)
        
        self.assertIn("idGenerator", functions)
        self.assertEqual(functions["idGenerator"].type, "generator_function_declaration")