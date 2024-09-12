from helper import *

x = 17055631616086234261032031094173218525702034438547941793769507244544508470535
y = 19978018089975334447263075061117870031074633264197647338396431905330906657895

x_cube = x**3
y_square = y**2

b = y_square - x_cube

# print(f" x_cube: {x_cube}")
# print(f" y_square: {y_square}")
# print(f" b: {b}")

X = 1 
Y = FindYforX(X)
print(Y)