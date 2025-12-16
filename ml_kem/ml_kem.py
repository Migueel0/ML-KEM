import random
import hashlib
import secrets

class ML_KEM:
    def __init__(self,n,q,k,e1,e2,du,dv):
        self.n = n
        self.q = q
        self.k = k
        self.e1 = e1
        self.e2 = e2
        self.du = du
        self.dv = dv

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
    
    def centered_binomial_distribution(self,buf,error):
        seed = bytes(buf)
        random.seed(seed)

        coefficients = []
        for _ in range(self.n):
            a = sum(random.randint(0,1) for _ in range (error))
            b = sum(random.randint(0,1) for _ in range(error))

            coefficients.append((a-b) % self.q)
        return coefficients




    def gen_matrix(self, r):
        """Generate matrix A from seed rho."""
        A = []
        for i in range(self.k):
            row = []
            for j in range(self.k):
                seed = r + bytes([i, j])
                h = hashlib.shake_128(seed).digest(self.n * 2)
                coefficients = []
                for k in range(0, len(h), 2):
                    val = int.from_bytes(h[k:k+2], 'little')
                    coefficients.append(val % self.q)
                row.append(coefficients[:self.n])
            A.append(row)
        return A
    
    def get_noise(self, sigma, nonce, error):
        """Generate noise vector/polynomial from seed sigma and nonce."""
        seed = sigma + bytes([nonce])
        return self.centered_binomial_distribution(seed,error)
    
    def pke_keygen(self):

        """CPA-PKE Key Generation."""
        d = secrets.token_bytes(32)
        r, sigma = d[:16], d[16:]
        hash_out = hashlib.sha3_512(d).digest()
        r, sigma = hash_out[:32], hash_out[32:]
        
        A = self.gen_matrix(r)
        
        s = [] 
        e = [] 
        N = 0

        for i in range(self.k):
            s.append(self.get_noise(sigma, N, self.e1))
            N += 1
        for _ in range(self.k):
            e.append(self.get_noise(sigma, N, self.e2))
            N += 1
            
        t = self.vector_sum(self.matrix_vector_multiplication(A, s), e)
        
        public_key = (t, r)
        secret_key = s

        return public_key, secret_key
    

    def pke_encrypt(self, pk, m, coins):
        """CPA-PKE Encryption."""
        t, r = pk
        A = self.gen_matrix(r)
        
        r = []
        N = 0
        for i in range(self.k):
            r.append(self.centered_binomial_distribution(coins + bytes([N]), self.e1))
            N += 1
            
        e1 = []
        for i in range(self.k):
            e1.append(self.centered_binomial_distribution(coins + bytes([N]), self.e2))
            N += 1
            
        e2 = self.centered_binomial_distribution(coins + bytes([N]), self.e2)

        AT = [[A[j][i] for j in range(self.k)] for i in range(self.k)]
        
        u = self.vector_sum(self.matrix_vector_multiplication(AT, r), e1)
        
        v_pol = self.vector_dot_product(t, r)
        v_pol = self.polynomials_sum(v_pol, e2)
        
        m_pol = []
    
        m_int = int.from_bytes(m, 'big')
        for i in range(self.n):
            bit = (m_int >> i) & 1
            if bit:
                m_pol.append(round(self.q / 2))
            else:
                m_pol.append(0)
        
        v = self.poly_add(v_pol, m_pol)
        
        c1 = [self.polynomial_compress(p, self.du) for p in u]
        c2 = self.polynomial_compress(v, self.dv)
        
        return (c1, c2)
    
    def pke_decrypt(self, sk, c):
        """CPA-PKE Decryption."""
        c1, c2 = c
        s = sk
        
        u = [self.polynomial_decompresss(p, self.du) for p in c1]
        v = self.polynomial_decompresss(c2, self.dv)
        
        prod = self.vector_dot_product(s, u)
        m_noisy = self.polynomials_sum(v, prod)
        
        m = bytearray(32)
        m_int = 0
        for i in range(self.n):
            val = m_noisy[i]
            
            if (self.q // 4) < val < (3 * self.q // 4):
                bit = 1
            else:
                bit = 0
            
            if bit:
                m_int |= (1 << i)
                
        return m_int.to_bytes(32, 'big')    