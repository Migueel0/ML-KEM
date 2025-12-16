import random

class ML_KEM:
    def __init__(self,n,q,k,e1,e2):
        self.n = n
        self.q = q
        self.k = k
        self.e1 = e1
        self.e2 = e2

    def polynomials_sum(self,a,b):
        return [(x + y) % self.q for x,y in zip(a,b)]
    
    def polynomials_substraction(self,a,b):
        return[(x  - y) % self.q for x,y in zip(a,b)]
    
    def polynomials_multiplication(self,a,b):

        res = [0] * [2 * self.n]
        for i in range(self.n):
            for j in range(self.n):
                res[i+j] = (res[i+j] + a[i] * b[j]) % self.q

        out = [0] * self.n

        for i in range(2 * self.n):
            if i < self.n:
                out[i] = (out[i] + res[i]) % self.q
            else:
                out[i - self.n] = (out[i - self.n] - res[i]) % self.q
        return out
    
    def vector_sum(self,v1,v2):
        return[self.polynomials_sum(p1,p2) for p1,p2 in zip(v1,v2)]
    
    def vector_dot_product(self,v1,v2):
        res = [0] * self.n
        for p1, p2 in zip(v1, v2):
            res = self.polynomials_sum(res, self.polynomials_sum(p1, p2))
        return res
    
    def matrix_vector_multiplication(self,M,v):
        """Multiply matrix M by vector v."""

        res = []
        for row in M:
            res.append(self.vec_dot(row, v))
        return res

    def compress(self, x, d):
        """Compress integer x from mod q to d bits."""
        return round((2**d / self.q) * x) % (2**d)

    def decompress(self, x, d):
        """Decompress integer x from d bits to mod q."""
        return round((self.q / 2**d) * x)
    
    def polynomial_compress(self,pol,d):
        return [self.compress(c,d) for c in pol]
    
    def polynomial_decompresss(self,pol,d):
        return [self.decompress(c,d) for c in pol]
    
    def centered_binomial_distribution(self,buf,e):
        seed = bytes(buf)
        random.seed(seed)

        coefficients = []
        for _ in range(self.n):
            a = sum(random.randint(0,1) for _ in range (e))
            b = sum(random.randint(0,1) for _ in range(e))

            coefficients.append((a-b) % self.q)
        return coefficients
