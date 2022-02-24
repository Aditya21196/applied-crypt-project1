"""
Module for generating random noise samples
"""
import random
import statistics


P = .35 #prob random character
NUM_RANDOM_CHARS = int(500 / (1 - P))-500
NUM_OF_EXPERIMENTS = 10
ALPHABET = " abcdefghijklmnopqrstuvwxyz"



def generate_random_encryption_noise_sample(length_of_noise):
    """
    length of noise is the number of noise chars
    """
    sample = []
    for i in range(length_of_noise):
        val = random.randint(0, len(ALPHABET) - 1)
        sample.append(val)
    return sample

def report_sample_stats(sample_list):
    """
    Gather stats
    """
    stats = [0] * len(ALPHABET)
    stats_dict = {}
    for sample in sample_list:
        stats[sample] += 1
    stats_dict["min"] = min(stats)
    stats_dict["max"] = max(stats)
    stats_dict["sd"] = statistics.stdev(stats)
    stats_dict["median"] = statistics.median(stats)
    stats_dict["mode"] = statistics.mode(stats)
    stats_dict["range"] = stats_dict["max"] - stats_dict["min"]
    stats_dict["num_of_samples_in_experiment"] = sum(stats)
    stats_dict["stats"] = stats
    stats_dict["diff_from_min"] = [x - stats_dict["min"] for x in stats]
    stats_dict["diff_from_med"] = [x - stats_dict["median"] for x in stats]
    stats_dict["diff_from_mod"] = [x - stats_dict["mode"] for x in stats]
    stats_dict["sum_dif_min"] = sum(stats_dict["diff_from_min"])
    stats_dict["sum_dif_med"] = sum(stats_dict["diff_from_med"])
    stats_dict["sum_dif_mod"] = sum(stats_dict["diff_from_mod"])
    for key, value in stats_dict.items():
        print(f"{key} : {value}")

def main():
    """
    Main function from CLI
    """
    for i in range(NUM_OF_EXPERIMENTS):
        print(f"Experiment {i} Random Noise Generation")
        samp = generate_random_encryption_noise_sample(NUM_RANDOM_CHARS)
        report_sample_stats(samp)
        print()

    # todo - generate stats for mean of experiment statistics


if __name__ == "__main__":
    main()
