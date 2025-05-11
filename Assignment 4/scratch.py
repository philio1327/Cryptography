from itertools import product

pop_sizes = [50, 100, 200]
num_generations = [100, 200, 500]
crossover = [0.7, 0.8, 0.9]
mutation = [0.01, 0.05, 0.1]
elite = [0.01, 0.02, 0.05]
selection = ['tournament', 'roulette']
count = 0
for pop in pop_sizes:
    for num in num_generations:
        for cross in crossover:
            for mut in mutation:
                for el in elite:
                    for sel in selection:
                        count += 1
                        print(f"Combo {count}: {pop, num, cross, mut, el, sel}")

param_combos = product(pop_sizes, num_generations, crossover, mutation, elite, selection)
print("Product Usage")
for combo in param_combos:
    print(combo)