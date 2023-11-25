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
    positive_match = [p for p in pattern_list if not p.startswith("-")]
    negative_match = [p[1:] for p in pattern_list if p.startswith("-")]

    pos_regex = "".join(f"(?=.*{m})" for m in positive_match)
    neg_regex = f"(^((?!{'|'.join(negative_match)}).)*$)" if negative_match else ""

    return pos_regex + neg_regex

