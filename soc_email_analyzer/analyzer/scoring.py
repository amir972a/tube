class ScoreEngine:
    def __init__(self):
        # Weights for different severities
        self.weights = {
            'Critical': 40,
            'High': 25,
            'Medium': 10,
            'Low': 5,
            'Informational': 0
        }

    def calculate(self, findings):
        score = 0
        explanations = []

        # Track categories to avoid massive double-counting
        # e.g., if we have 5 'Low' urgency keywords, we don't want to add 25 points
        category_counts = {}

        for finding in findings:
            severity = finding.get('severity', 'Informational')
            category = finding.get('category', 'Unknown')

            category_counts[category] = category_counts.get(category, 0) + 1

            # Apply diminishing returns for multiple findings in the same category
            # 1st finding: 100% weight
            # 2nd finding: 50% weight
            # 3rd+ finding: 0% weight (capped)

            base_weight = self.weights.get(severity, 0)

            if category_counts[category] == 1:
                weight = base_weight
            elif category_counts[category] == 2:
                weight = base_weight // 2
            else:
                weight = 0

            if weight > 0:
                score += weight
                explanations.append(f"+{weight} points: {severity} finding in '{category}'")

        # Cap score at 100
        final_score = min(score, 100)

        # Determine overall severity based on final score
        if final_score >= 80:
            overall_severity = 'Critical'
        elif final_score >= 60:
            overall_severity = 'High'
        elif final_score >= 30:
            overall_severity = 'Medium'
        elif final_score > 0:
            overall_severity = 'Low'
        else:
            overall_severity = 'Informational'

        return final_score, overall_severity, explanations
