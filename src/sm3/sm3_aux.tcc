#ifndef SM3_AUX_TCC_
#define SM3_AUX_TCC_

namespace libsnark
{
    template <typename FieldT>
    ff_gadget<FieldT>::ff_gadget(protoboard<FieldT> &pb,
                                 const pb_linear_combination_array<FieldT> &X,
                                 const pb_linear_combination_array<FieldT> &Y,
                                 const pb_linear_combination_array<FieldT> &Z,
                                 const size_t i,
                                 const pb_variable<FieldT> &result, const std::string &annotation_prefix) : gadget<FieldT>(pb, annotation_prefix),
                                                                                                            result(result),
                                                                                                            i(i)
    {
        result_bits.allocate(pb, 32, FMT(this->annotation_prefix, " result_bits"));
        if (i < 16)
        {
            parity.reset(new parity_gadget<FieldT>(pb, X, Y, Z, false, 0, 0, 0, result_bits, " ff_parity"));
            pack_parity_result.reset(new packing_gadget<FieldT>(pb, result_bits, result, " ff_parity_packing"));
        }
        else
        {
            majority.reset(new majority_gadget<FieldT>(pb, X, Y, Z, result, "ff_majority"));
        }
    }

    template <typename FieldT>
    void ff_gadget<FieldT>::generate_r1cs_constraints()
    {
        if (i < 16)
        {
            parity->generate_r1cs_constraints();
            pack_parity_result->generate_r1cs_constraints(false);
        }
        else
        {
            majority->generate_r1cs_constraints();
        }
    }

    template <typename FieldT>
    void ff_gadget<FieldT>::generate_r1cs_witness()
    {
        if (i < 16)
        {
            parity->generate_r1cs_witness();
            pack_parity_result->generate_r1cs_witness_from_bits();
        }
        else
        {
            majority->generate_r1cs_witness();
        }
    }

    template <typename FieldT>
    gg_gadget<FieldT>::gg_gadget(protoboard<FieldT> &pb,
                                 const pb_linear_combination_array<FieldT> &X,
                                 const pb_linear_combination_array<FieldT> &Y,
                                 const pb_linear_combination_array<FieldT> &Z,
                                 const size_t i,
                                 const pb_variable<FieldT> &result, const std::string &annotation_prefix) : gadget<FieldT>(pb, annotation_prefix),
                                                                                                            result(result),
                                                                                                            i(i)
    {
        result_bits.allocate(pb, 32, FMT(this->annotation_prefix, " result_bits"));
        if (i < 16)
        {
            parity.reset(new parity_gadget<FieldT>(pb, X, Y, Z, false, 0, 0, 0, result_bits, " gg_parity"));
            pack_parity_result.reset(new packing_gadget<FieldT>(pb, result_bits, result, " gg_parity_packing"));
        }
        else
        {
            choice.reset(new choice_gadget<FieldT>(pb, X, Y, Z, result, "gg_choice"));
        }
    }

    template <typename FieldT>
    void gg_gadget<FieldT>::generate_r1cs_constraints()
    {
        if (i < 16)
        {
            parity->generate_r1cs_constraints();
            pack_parity_result->generate_r1cs_constraints(false);
        }
        else
        {
            choice->generate_r1cs_constraints();
        }
    }

    template <typename FieldT>
    void gg_gadget<FieldT>::generate_r1cs_witness()
    {
        if (i < 16)
        {
            parity->generate_r1cs_witness();
            pack_parity_result->generate_r1cs_witness_from_bits();
        }
        else
        {
            choice->generate_r1cs_witness();
        }
    }

#define SM3_GADGET_ROTL(A, i, k) A[((i) - (k)) % 32]

    template <typename FieldT>
    parity_gadget<FieldT>::parity_gadget(protoboard<FieldT> &pb,
                                         const pb_linear_combination_array<FieldT> &X,
                                         const pb_linear_combination_array<FieldT> &Y,
                                         const pb_linear_combination_array<FieldT> &Z,
                                         const bool assume_Z_is_zero,
                                         const size_t rot1,
                                         const size_t rot2,
                                         const size_t rot3,
                                         const pb_variable_array<FieldT> &result_bits,
                                         const std::string &annotation_prefix) : gadget<FieldT>(pb, annotation_prefix),
                                                                                 X(X),
                                                                                 Y(Y),
                                                                                 Z(Z),
                                                                                 result_bits(result_bits),
                                                                                 pb(pb)
    {
        //result_bits.allocate(pb, 32, FMT(this->annotation_prefix, " result_bits"));
        compute_bits.resize(32);
        for (size_t i = 0; i < 32; i++)
        {
            compute_bits[i].reset(new XOR3_gadget<FieldT>(pb, SM3_GADGET_ROTL(X, i, rot1), SM3_GADGET_ROTL(Y, i, rot2), SM3_GADGET_ROTL(Z, i, rot3), assume_Z_is_zero, result_bits[i],
                                                          FMT(this->annotation_prefix, " compute_bits_%zu", i)));
        }
    }

    template <typename FieldT>
    void parity_gadget<FieldT>::generate_r1cs_constraints()
    {
        for (size_t i = 0; i < 32; ++i)
        {
            compute_bits[i]->generate_r1cs_constraints();
        }
    }

    template <typename FieldT>
    void parity_gadget<FieldT>::generate_r1cs_witness()
    {
        for (size_t i = 0; i < 32; ++i)
        {
            compute_bits[i]->generate_r1cs_witness();
        }
    }

    template <typename FieldT>
    permutation_gadget<FieldT>::permutation_gadget(
        protoboard<FieldT> &pb,
        const pb_linear_combination_array<FieldT> &X,
        const pb_linear_combination_array<FieldT> &result_bits,
        const size_t rot1,
        const size_t rot2,
        const size_t rot3,
        const std::string &annotation_prefix) : gadget<FieldT>(pb, annotation_prefix),
                                                X(X),
                                                result_bits(result_bits)
    {
        //result_bits.resize(32);
        compute_bits.resize(32);
        for (size_t i = 0; i < 32; ++i)
        {
            compute_bits[i].reset(new XOR3_gadget<FieldT>(pb, SM3_GADGET_ROTL(X, i, rot1), SM3_GADGET_ROTL(X, i, rot2), SM3_GADGET_ROTL(X, i, rot3), false, result_bits[i],
                                                          FMT(this->annotation_prefix, " compute_bits_%zu", i)));
        }
    }

    template <typename FieldT>
    void permutation_gadget<FieldT>::generate_r1cs_constraints()
    {
        for (size_t i = 0; i < 32; ++i)
        {
            compute_bits[i]->generate_r1cs_constraints();
        }
    }

    template <typename FieldT>
    void permutation_gadget<FieldT>::generate_r1cs_witness()
    {
        for (size_t i = 0; i < 32; ++i)
        {
            compute_bits[i]->generate_r1cs_witness();
        }
    }

    template <typename FieldT>
    pb_linear_combination_array<FieldT> rotate_left(const pb_linear_combination_array<FieldT> &pre, size_t rot)
    {
        pb_linear_combination_array<FieldT> after;
        after.resize(32);
        for (size_t i = 0; i < 32; i++)
        {
            after[i] = SM3_GADGET_ROTL(pre, i, rot);
        }
        return after;
    }

} // libsnark

#endif // SM3_AUX_TCC_