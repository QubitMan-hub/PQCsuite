public sealed class SignerFactory
{
    public ISigner Create(JwtAlg alg)
    {
        switch (alg)
        {
            case JwtAlg.RS256:
            case JwtAlg.ES256:
                throw new NotSupportedException("asymmetric keys are handled elsewhere");
            case JwtAlg.HS256:
                return new MacSigner(alg);
            default:
                throw new ArgumentOutOfRangeException(nameof(alg));
        }
    }
}
