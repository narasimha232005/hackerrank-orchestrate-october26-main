import pandas as pd
u = pd.read_csv('dataset/user_identities.csv')
print(u[u['user_id'] == 'user_12'])
