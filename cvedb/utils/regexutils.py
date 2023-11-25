def process_pattern(pattern: str):
    """
    Process a string pattern and generate a regular expression (regex) based on the pattern.

    The pattern is a string of words separated by spaces. Each word represents a match condition.
    If a word starts with "-", it represents a negative match condition, otherwise it represents a positive match condition.

    :param pattern: The pattern string to be processed.
    :return: A regex string that matches any string satisfying all the positive and negative match conditions.

    :Example:

    >>> process_pattern("apple -orange")
    '(?=.*apple)(^((?!orange).)*$)'

    This will return a regex that matches any string that contains "apple" and does not contain "orange".
    """
    pattern_list = pattern.split(" ")
    postivie_match = []
    negative_match = []

    for p in pattern_list:
        if p[0] == "-":
            negative_match.append(p[1:])
        else:
            postivie_match.append(p)

    pos_regex = "" # (?=.*m1)(?=.*m2)
    for m in postivie_match:
        r = f"(?=.*{m})"
        pos_regex += r

    # (^((?!(m1|m2)).)*$)
    neg_regex = f"(^((?!({'|'.join(negative_match)})).)*$)"

    return pos_regex + neg_regex

