#ifndef SM3_COMPONENTS_TCC_
#define SM3_COMPONENTS_TCC_

namespace libsnark
{
    const unsigned long sm3_H[8] = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e};

    template <typename FieldT>
    pb_linear_combination_array<FieldT> sm3_default_IV(protoboard<FieldT> &pb)
    {
        pb_linear_combination_array<FieldT> result;
        result.reserve(sm3_digest_size);

        for (size_t i = 0; i < sm3_digest_size; ++i)
        {
            int iv_val = (sm3_H[i / 32] >> (31 - (i % 32))) & 1;

            pb_linear_combination<FieldT> iv_element;
            iv_element.assign(pb, iv_val * ONE);
            iv_element.evaluate(pb);

            result.emplace_back(iv_element);
        }

        return result;
    }

    template <typename FieldT>
    sm3_message_schedule_gadget<FieldT>::sm3_message_schedule_gadget(protoboard<FieldT> &pb,
                                                                     const pb_variable_array<FieldT> &M,
                                                                     const pb_variable_array<FieldT> &packed_W,
                                                                     const pb_variable_array<FieldT> &packed_W_extended,
                                                                     const std::string &annotation_prefix) : gadget<FieldT>(pb, annotation_prefix),
                                                                                                             M(M),
                                                                                                             packed_W(packed_W),
                                                                                                             packed_W_extended(packed_W_extended)
    {
        W_bits.resize(68);
        W_extended_bits.resize(64);

        pack_W.resize(16);
        for (size_t i = 0; i < 16; ++i)
        {
            W_bits[i] = pb_variable_array<FieldT>(M.rbegin() + (15 - i) * 32, M.rbegin() + (16 - i) * 32);
            pack_W[i].reset(new packing_gadget<FieldT>(pb, W_bits[i], packed_W[i], FMT(this->annotation_prefix, " pack_W_%zu", i)));
        }

        /* NB: some of those will be un-allocated */
        sigma0.resize(64);
        sigma1.resize(64);
        compute_sigma0.resize(64);
        compute_sigma1.resize(64);

        for (size_t i = 16; i < 64; ++i)
        {
            /* allocate result variables for sigma0/sigma1 invocations */
            sigma0[i].allocate(pb, FMT(this->annotation_prefix, " sigma0_%zu", i));
            sigma1[i].allocate(pb, FMT(this->annotation_prefix, " sigma1_%zu", i));

            /* compute sigma0/sigma1 */
            compute_sigma0[i].reset(new small_sigma_gadget<FieldT>(pb, W_bits[i - 15], sigma0[i], 7, 18, 3, FMT(this->annotation_prefix, " compute_sigma0_%zu", i)));
            compute_sigma1[i].reset(new small_sigma_gadget<FieldT>(pb, W_bits[i - 2], sigma1[i], 17, 19, 10, FMT(this->annotation_prefix, " compute_sigma1_%zu", i)));

            /* unreduced_W = sigma0(W_{i-15}) + sigma1(W_{i-2}) + W_{i-7} + W_{i-16} before modulo 2^32 */
            unreduced_W[i].allocate(pb, FMT(this->annotation_prefix, " unreduced_W_%zu", i));

            /* allocate the bit representation of packed_W[i] */
            W_bits[i].allocate(pb, 32, FMT(this->annotation_prefix, " W_bits_%zu", i));

            /* and finally reduce this into packed and bit representations */
            mod_reduce_W[i].reset(new lastbits_gadget<FieldT>(pb, unreduced_W[i], 32 + 2, packed_W[i], W_bits[i], FMT(this->annotation_prefix, " mod_reduce_W_%zu", i)));
        }

        for (size_t i = 0; i < 64; ++i)
        {
        }
    }

    template <typename FieldT>
    void sm3_message_schedule_gadget<FieldT>::generate_r1cs_constraints()
    {
        for (size_t i = 0; i < 16; ++i)
        {
            pack_W[i]->generate_r1cs_constraints(false); // do not enforce bitness here; caller be aware. //可以减少constraint数
        }

        for (size_t i = 16; i < 64; ++i)
        {
            compute_sigma0[i]->generate_r1cs_constraints();
            compute_sigma1[i]->generate_r1cs_constraints();

            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1,
                                                                 sigma0[i] + sigma1[i] + packed_W[i - 16] + packed_W[i - 7],
                                                                 unreduced_W[i]),
                                         FMT(this->annotation_prefix, " unreduced_W_%zu", i));

            mod_reduce_W[i]->generate_r1cs_constraints();
        }
    }

    template <typename FieldT>
    void sm3_message_schedule_gadget<FieldT>::generate_r1cs_witness()
    {
        for (size_t i = 0; i < 16; ++i)
        {
            pack_W[i]->generate_r1cs_witness_from_bits();
        }

        for (size_t i = 16; i < 64; ++i)
        {
            compute_sigma0[i]->generate_r1cs_witness();
            compute_sigma1[i]->generate_r1cs_witness();
            this->pb.val(unreduced_W[i]) = this->pb.val(sigma0[i]) + this->pb.val(sigma1[i]) + this->pb.val(packed_W[i - 16]) + this->pb.val(packed_W[i - 7]);
            mod_reduce_W[i]->generate_r1cs_witness();
        }
    }

    template <typename FieldT>
    sm3_round_function_gadget<FieldT>::sm3_round_function_gadget(protoboard<FieldT> &pb,
                                                                 const pb_linear_combination_array<FieldT> &a,
                                                                 const pb_linear_combination_array<FieldT> &b,
                                                                 const pb_linear_combination_array<FieldT> &c,
                                                                 const pb_linear_combination_array<FieldT> &d,
                                                                 const pb_linear_combination_array<FieldT> &e,
                                                                 const pb_linear_combination_array<FieldT> &f,
                                                                 const pb_linear_combination_array<FieldT> &g,
                                                                 const pb_linear_combination_array<FieldT> &h,
                                                                 const pb_variable<FieldT> &W,
                                                                 const pb_variable<FieldT> &W_extended,
                                                                 const pb_linear_combination_array<FieldT> &new_a,
                                                                 const pb_linear_combination_array<FieldT> &new_e,
                                                                 const size_t i,
                                                                 const std::string &annotation_prefix) : gadget<FieldT>(pb, annotation_prefix),
                                                                                                         a(a),
                                                                                                         b(b),
                                                                                                         c(c),
                                                                                                         d(d),
                                                                                                         e(e),
                                                                                                         f(f),
                                                                                                         g(g),
                                                                                                         h(h),
                                                                                                         W(W),
                                                                                                         W_extended(W_extended),
                                                                                                         new_a(new_a),
                                                                                                         new_e(new_e),
                                                                                                         i(i)
    {
        /* compute sigma0 and sigma1 */
        sigma0.allocate(pb, FMT(this->annotation_prefix, " sigma0"));
        sigma1.allocate(pb, FMT(this->annotation_prefix, " sigma1"));
        compute_sigma0.reset(new big_sigma_gadget<FieldT>(pb, a, sigma0, 2, 13, 22, FMT(this->annotation_prefix, " compute_sigma0")));
        compute_sigma1.reset(new big_sigma_gadget<FieldT>(pb, e, sigma1, 6, 11, 25, FMT(this->annotation_prefix, " compute_sigma1")));

        /* compute choice */
        choice.allocate(pb, FMT(this->annotation_prefix, " choice"));
        compute_choice.reset(new choice_gadget<FieldT>(pb, e, f, g, choice, FMT(this->annotation_prefix, " compute_choice")));

        /* compute majority */
        majority.allocate(pb, FMT(this->annotation_prefix, " majority"));
        compute_majority.reset(new majority_gadget<FieldT>(pb, a, b, c, majority, FMT(this->annotation_prefix, " compute_majority")));

        /* pack d */
        packed_d.allocate(pb, FMT(this->annotation_prefix, " packed_d"));
        pack_d.reset(new packing_gadget<FieldT>(pb, d, packed_d, FMT(this->annotation_prefix, " pack_d")));

        /* pack h */
        packed_h.allocate(pb, FMT(this->annotation_prefix, " packed_h"));
        pack_h.reset(new packing_gadget<FieldT>(pb, h, packed_h, FMT(this->annotation_prefix, " pack_h")));

        /* compute the actual results for the round */
        unreduced_new_a.allocate(pb, FMT(this->annotation_prefix, " unreduced_new_a"));
        unreduced_new_e.allocate(pb, FMT(this->annotation_prefix, " unreduced_new_e"));

        packed_new_a.allocate(pb, FMT(this->annotation_prefix, " packed_new_a"));
        packed_new_e.allocate(pb, FMT(this->annotation_prefix, " packed_new_e"));

        mod_reduce_new_a.reset(new lastbits_gadget<FieldT>(pb, unreduced_new_a, 32 + 3, packed_new_a, new_a, FMT(this->annotation_prefix, " mod_reduce_new_a")));
        mod_reduce_new_e.reset(new lastbits_gadget<FieldT>(pb, unreduced_new_e, 32 + 3, packed_new_e, new_e, FMT(this->annotation_prefix, " mod_reduce_new_e")));
    }

    template <typename FieldT>
    void sm3_round_function_gadget<FieldT>::generate_r1cs_constraints()
    {
        compute_sigma0->generate_r1cs_constraints();
        compute_sigma1->generate_r1cs_constraints();

        compute_choice->generate_r1cs_constraints();
        compute_majority->generate_r1cs_constraints();

        pack_d->generate_r1cs_constraints(false);
        pack_h->generate_r1cs_constraints(false);

        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1,
                                                             packed_h + sigma1 + choice + K + W + sigma0 + majority,
                                                             unreduced_new_a),
                                     FMT(this->annotation_prefix, " unreduced_new_a"));

        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1,
                                                             packed_d + packed_h + sigma1 + choice + K + W,
                                                             unreduced_new_e),
                                     FMT(this->annotation_prefix, " unreduced_new_e"));

        mod_reduce_new_a->generate_r1cs_constraints();
        mod_reduce_new_e->generate_r1cs_constraints();
    }

    template <typename FieldT>
    void sm3_round_function_gadget<FieldT>::generate_r1cs_witness()
    {
        compute_sigma0->generate_r1cs_witness();
        compute_sigma1->generate_r1cs_witness();

        compute_choice->generate_r1cs_witness();
        compute_majority->generate_r1cs_witness();

        pack_d->generate_r1cs_witness_from_bits();
        pack_h->generate_r1cs_witness_from_bits();

        this->pb.val(unreduced_new_a) = this->pb.val(packed_h) + this->pb.val(sigma1) + this->pb.val(choice) + FieldT(K) + this->pb.val(W) + this->pb.val(sigma0) + this->pb.val(majority);
        this->pb.val(unreduced_new_e) = this->pb.val(packed_d) + this->pb.val(packed_h) + this->pb.val(sigma1) + this->pb.val(choice) + FieldT(K) + this->pb.val(W);

        mod_reduce_new_a->generate_r1cs_witness();
        mod_reduce_new_e->generate_r1cs_witness();
    }
} // libsnark

#endif // SM3_COMPONENTS_TCC_