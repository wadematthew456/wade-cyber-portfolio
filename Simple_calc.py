num = float(input("Enter a number: "))
num2 = float(input("Enter another number: "))
num3 = input("Enter an operator (+, -, *, /): ")

if num3 == "+":
    result = num + num2
    print(f"The result of {num} + {num2} is: {result}")
elif num3 == "-":
    result = num - num2
    print(f"The result of {num} - {num2} is: {result}")
elif num3 == "*":
    result = num * num2
    print(f"The result of {num} * {num2} is: {result}")
elif num3 == "/":
    result = num / num2
    print(f"The result of {num} / {num2} is: {result}")
else:
    print("Invalid operator. Please use +, -, *, or /.")

